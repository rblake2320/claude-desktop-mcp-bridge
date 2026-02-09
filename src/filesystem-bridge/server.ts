#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from '@modelcontextprotocol/sdk/types.js';
import { readFile, writeFile, access } from 'fs/promises';
import { glob } from 'glob';
import { dirname, resolve, relative } from 'path';
import { z } from 'zod';

// Configuration schema
const ConfigSchema = z.object({
  allowedPaths: z.array(z.string()).default([process.cwd()]),
  maxFileSize: z.number().default(10 * 1024 * 1024), // 10MB
  readOnly: z.boolean().default(false),
});

type Config = z.infer<typeof ConfigSchema>;

class FilesystemBridge {
  private config: Config;

  constructor(config: Partial<Config> = {}) {
    this.config = ConfigSchema.parse(config);
  }

  /**
   * Check if a path is within allowed paths
   */
  private isPathAllowed(filePath: string): boolean {
    const resolvedPath = resolve(filePath);
    return this.config.allowedPaths.some(allowedPath => {
      const resolvedAllowed = resolve(allowedPath);
      return resolvedPath.startsWith(resolvedAllowed);
    });
  }

  /**
   * Read file contents with line numbers (like Claude Code's Read tool)
   */
  async readFile(filePath: string, offset?: number, limit?: number): Promise<string> {
    if (!this.isPathAllowed(filePath)) {
      throw new Error(`Access denied: ${filePath} is not in allowed paths`);
    }

    try {
      const content = await readFile(filePath, 'utf-8');
      const lines = content.split('\n');

      const startLine = offset || 0;
      const endLine = limit ? startLine + limit : lines.length;

      return lines
        .slice(startLine, endLine)
        .map((line, index) => `${startLine + index + 1}→${line}`)
        .join('\n');
    } catch (error) {
      throw new Error(`Failed to read file ${filePath}: ${error.message}`);
    }
  }

  /**
   * Write file contents (like Claude Code's Write tool)
   */
  async writeFile(filePath: string, content: string): Promise<string> {
    if (this.config.readOnly) {
      throw new Error('Write operations are disabled in read-only mode');
    }

    if (!this.isPathAllowed(filePath)) {
      throw new Error(`Access denied: ${filePath} is not in allowed paths`);
    }

    if (content.length > this.config.maxFileSize) {
      throw new Error(`File size exceeds maximum allowed size of ${this.config.maxFileSize} bytes`);
    }

    try {
      // Ensure directory exists
      const dir = dirname(filePath);
      await access(dir).catch(async () => {
        throw new Error(`Directory ${dir} does not exist`);
      });

      await writeFile(filePath, content, 'utf-8');
      return `File written successfully: ${filePath}`;
    } catch (error) {
      throw new Error(`Failed to write file ${filePath}: ${error.message}`);
    }
  }

  /**
   * Edit file with exact string replacement (like Claude Code's Edit tool)
   */
  async editFile(filePath: string, oldString: string, newString: string, replaceAll = false): Promise<string> {
    if (this.config.readOnly) {
      throw new Error('Edit operations are disabled in read-only mode');
    }

    if (!this.isPathAllowed(filePath)) {
      throw new Error(`Access denied: ${filePath} is not in allowed paths`);
    }

    try {
      const content = await readFile(filePath, 'utf-8');

      let newContent: string;
      if (replaceAll) {
        newContent = content.replaceAll(oldString, newString);
      } else {
        // Check if oldString is unique
        const occurrences = content.split(oldString).length - 1;
        if (occurrences === 0) {
          throw new Error(`String not found: ${oldString}`);
        }
        if (occurrences > 1) {
          throw new Error(`String is not unique (found ${occurrences} occurrences). Use replaceAll=true or provide more context.`);
        }
        newContent = content.replace(oldString, newString);
      }

      await writeFile(filePath, newContent, 'utf-8');
      return `File edited successfully: ${filePath}`;
    } catch (error) {
      throw new Error(`Failed to edit file ${filePath}: ${error.message}`);
    }
  }

  /**
   * Find files by pattern (like Claude Code's Glob tool)
   */
  async globSearch(pattern: string, basePath?: string): Promise<string[]> {
    const searchPath = basePath && this.isPathAllowed(basePath) ? basePath : this.config.allowedPaths[0];

    try {
      const files = await glob(pattern, {
        cwd: searchPath,
        absolute: true,
        follow: false, // Don't follow symlinks for security
      });

      // Filter out files not in allowed paths
      const allowedFiles = files.filter(file => this.isPathAllowed(file));

      // Return relative paths for easier reading
      return allowedFiles.map(file => relative(searchPath, file));
    } catch (error) {
      throw new Error(`Failed to search for pattern ${pattern}: ${error.message}`);
    }
  }
}

// Initialize the filesystem bridge
const filesystem = new FilesystemBridge({
  allowedPaths: process.env.ALLOWED_PATHS?.split(',') || [process.cwd()],
  readOnly: process.env.READ_ONLY === 'true',
  maxFileSize: process.env.MAX_FILE_SIZE ? parseInt(process.env.MAX_FILE_SIZE) : undefined,
});

// Create MCP server
const server = new Server(
  {
    name: 'filesystem-bridge',
    version: '0.1.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Define tools
const tools: Tool[] = [
  {
    name: 'read_file',
    description: 'Read file contents with line numbers (like Claude Code Read tool)',
    inputSchema: {
      type: 'object',
      properties: {
        filePath: {
          type: 'string',
          description: 'Path to the file to read',
        },
        offset: {
          type: 'number',
          description: 'Line offset to start reading from (0-based)',
        },
        limit: {
          type: 'number',
          description: 'Maximum number of lines to read',
        },
      },
      required: ['filePath'],
    },
  },
  {
    name: 'write_file',
    description: 'Write content to a file (like Claude Code Write tool)',
    inputSchema: {
      type: 'object',
      properties: {
        filePath: {
          type: 'string',
          description: 'Path to the file to write',
        },
        content: {
          type: 'string',
          description: 'Content to write to the file',
        },
      },
      required: ['filePath', 'content'],
    },
  },
  {
    name: 'edit_file',
    description: 'Edit file with exact string replacement (like Claude Code Edit tool)',
    inputSchema: {
      type: 'object',
      properties: {
        filePath: {
          type: 'string',
          description: 'Path to the file to edit',
        },
        oldString: {
          type: 'string',
          description: 'String to replace',
        },
        newString: {
          type: 'string',
          description: 'String to replace with',
        },
        replaceAll: {
          type: 'boolean',
          description: 'Whether to replace all occurrences',
          default: false,
        },
      },
      required: ['filePath', 'oldString', 'newString'],
    },
  },
  {
    name: 'glob_search',
    description: 'Find files by pattern (like Claude Code Glob tool)',
    inputSchema: {
      type: 'object',
      properties: {
        pattern: {
          type: 'string',
          description: 'Glob pattern to search for (e.g., "**/*.ts", "src/**/*.js")',
        },
        basePath: {
          type: 'string',
          description: 'Base path to search from (optional)',
        },
      },
      required: ['pattern'],
    },
  },
];

// Register tool handlers
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return { tools };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'read_file': {
        const { filePath, offset, limit } = args as any;
        const result = await filesystem.readFile(filePath, offset, limit);
        return {
          content: [
            {
              type: 'text',
              text: result,
            },
          ],
        };
      }

      case 'write_file': {
        const { filePath, content } = args as any;
        const result = await filesystem.writeFile(filePath, content);
        return {
          content: [
            {
              type: 'text',
              text: result,
            },
          ],
        };
      }

      case 'edit_file': {
        const { filePath, oldString, newString, replaceAll } = args as any;
        const result = await filesystem.editFile(filePath, oldString, newString, replaceAll);
        return {
          content: [
            {
              type: 'text',
              text: result,
            },
          ],
        };
      }

      case 'glob_search': {
        const { pattern, basePath } = args as any;
        const files = await filesystem.globSearch(pattern, basePath);
        return {
          content: [
            {
              type: 'text',
              text: files.length > 0 ? files.join('\n') : 'No files found',
            },
          ],
        };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    return {
      content: [
        {
          type: 'text',
          text: `Error: ${error.message}`,
        },
      ],
      isError: true,
    };
  }
});

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Filesystem bridge MCP server running on stdio');
}

main().catch((error) => {
  console.error('Server failed to start:', error);
  process.exit(1);
});