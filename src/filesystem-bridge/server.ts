#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from '@modelcontextprotocol/sdk/types.js';
import { readFile, writeFile, mkdir } from 'fs/promises';
import { glob } from 'glob';
import { dirname, resolve, relative } from 'path';
import { z } from 'zod';
import { platform } from 'os';

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Normalise a path for cross-platform comparison (lowercase + forward slashes on Windows). */
function normalisePath(p: string): string {
  const resolved = resolve(p);
  if (platform() === 'win32') {
    return resolved.replace(/\\/g, '/').toLowerCase();
  }
  return resolved;
}

/** Extract a human-readable message from an unknown thrown value. */
function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

// ── Configuration ────────────────────────────────────────────────────────────

const ConfigSchema = z.object({
  allowedPaths: z.array(z.string()).default([process.cwd()]),
  maxFileSize: z.number().default(10 * 1024 * 1024), // 10 MB
  readOnly: z.boolean().default(false),
});

type Config = z.infer<typeof ConfigSchema>;

// ── Filesystem Bridge ────────────────────────────────────────────────────────

class FilesystemBridge {
  private config: Config;

  constructor(config: Partial<Config> = {}) {
    this.config = ConfigSchema.parse(config);
  }

  /** Check if a path is within allowed paths (cross-platform safe). */
  private isPathAllowed(filePath: string): boolean {
    const normTarget = normalisePath(filePath);
    return this.config.allowedPaths.some(allowed => {
      const normAllowed = normalisePath(allowed);
      // Ensure we match on directory boundaries
      return normTarget === normAllowed || normTarget.startsWith(normAllowed + '/');
    });
  }

  /** Read file contents with line numbers (like Claude Code's Read tool). */
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
        .map((line, index) => `${startLine + index + 1}\u2192${line}`)
        .join('\n');
    } catch (err) {
      throw new Error(`Failed to read file ${filePath}: ${errorMessage(err)}`);
    }
  }

  /** Write file contents, creating parent directories as needed. */
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
      // Bug fix #3: recursively create parent directories
      const dir = dirname(resolve(filePath));
      await mkdir(dir, { recursive: true });

      await writeFile(filePath, content, 'utf-8');
      return `File written successfully: ${filePath}`;
    } catch (err) {
      throw new Error(`Failed to write file ${filePath}: ${errorMessage(err)}`);
    }
  }

  /** Edit file with exact string replacement. */
  async editFile(
    filePath: string,
    oldString: string,
    newString: string,
    replaceAll = false,
  ): Promise<string> {
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
        const occurrences = content.split(oldString).length - 1;
        if (occurrences === 0) {
          throw new Error(`String not found: ${oldString}`);
        }
        if (occurrences > 1) {
          throw new Error(
            `String is not unique (found ${occurrences} occurrences). Use replaceAll=true or provide more context.`,
          );
        }
        newContent = content.replace(oldString, newString);
      }

      await writeFile(filePath, newContent, 'utf-8');
      return `File edited successfully: ${filePath}`;
    } catch (err) {
      throw new Error(`Failed to edit file ${filePath}: ${errorMessage(err)}`);
    }
  }

  /** Find files by glob pattern. */
  async globSearch(pattern: string, basePath?: string): Promise<string[]> {
    const searchPath =
      basePath && this.isPathAllowed(basePath) ? basePath : this.config.allowedPaths[0];

    try {
      const files = await glob(pattern, {
        cwd: searchPath,
        absolute: true,
        follow: false, // security: don't follow symlinks
      });

      const allowedFiles = files.filter(file => this.isPathAllowed(file));
      return allowedFiles.map(file => relative(searchPath, file));
    } catch (err) {
      throw new Error(`Failed to search for pattern ${pattern}: ${errorMessage(err)}`);
    }
  }
}

// ── Initialise ───────────────────────────────────────────────────────────────

const filesystem = new FilesystemBridge({
  allowedPaths: process.env.ALLOWED_PATHS?.split(',') || [process.cwd()],
  readOnly: process.env.READ_ONLY === 'true',
  maxFileSize: process.env.MAX_FILE_SIZE ? parseInt(process.env.MAX_FILE_SIZE, 10) : undefined,
});

const server = new Server(
  { name: 'filesystem-bridge', version: '0.2.0' },
  { capabilities: { tools: {} } },
);

// ── Tool definitions ─────────────────────────────────────────────────────────

const tools: Tool[] = [
  {
    name: 'read_file',
    description: 'Read file contents with line numbers (like Claude Code Read tool)',
    inputSchema: {
      type: 'object',
      properties: {
        filePath: { type: 'string', description: 'Path to the file to read' },
        offset: { type: 'number', description: 'Line offset to start reading from (0-based)' },
        limit: { type: 'number', description: 'Maximum number of lines to read' },
      },
      required: ['filePath'],
    },
  },
  {
    name: 'write_file',
    description: 'Write content to a file, creating parent directories as needed',
    inputSchema: {
      type: 'object',
      properties: {
        filePath: { type: 'string', description: 'Path to the file to write' },
        content: { type: 'string', description: 'Content to write to the file' },
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
        filePath: { type: 'string', description: 'Path to the file to edit' },
        oldString: { type: 'string', description: 'String to replace' },
        newString: { type: 'string', description: 'String to replace with' },
        replaceAll: { type: 'boolean', description: 'Whether to replace all occurrences', default: false },
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
        pattern: { type: 'string', description: 'Glob pattern (e.g., "**/*.ts")' },
        basePath: { type: 'string', description: 'Base path to search from (optional)' },
      },
      required: ['pattern'],
    },
  },
];

// ── Handlers ─────────────────────────────────────────────────────────────────

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'read_file': {
        const { filePath, offset, limit } = args as { filePath: string; offset?: number; limit?: number };
        const result = await filesystem.readFile(filePath, offset, limit);
        return { content: [{ type: 'text', text: result }] };
      }

      case 'write_file': {
        const { filePath, content } = args as { filePath: string; content: string };
        const result = await filesystem.writeFile(filePath, content);
        return { content: [{ type: 'text', text: result }] };
      }

      case 'edit_file': {
        const { filePath, oldString, newString, replaceAll } = args as {
          filePath: string; oldString: string; newString: string; replaceAll?: boolean;
        };
        const result = await filesystem.editFile(filePath, oldString, newString, replaceAll);
        return { content: [{ type: 'text', text: result }] };
      }

      case 'glob_search': {
        const { pattern, basePath } = args as { pattern: string; basePath?: string };
        const files = await filesystem.globSearch(pattern, basePath);
        return { content: [{ type: 'text', text: files.length > 0 ? files.join('\n') : 'No files found' }] };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (err) {
    return {
      content: [{ type: 'text', text: `Error: ${errorMessage(err)}` }],
      isError: true,
    };
  }
});

// ── Start ────────────────────────────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Filesystem bridge MCP server running on stdio');
}

main().catch((err) => {
  console.error('Server failed to start:', err);
  process.exit(1);
});
