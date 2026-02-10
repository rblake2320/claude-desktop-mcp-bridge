#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from '@modelcontextprotocol/sdk/types.js';
import { readFile, writeFile, mkdir, realpath, appendFile } from 'fs/promises';
import { existsSync, mkdirSync } from 'fs';
import { glob } from 'glob';
import { dirname, resolve, relative, join, sep } from 'path';
import { z } from 'zod';
import { platform } from 'os';

// ── Helpers ──────────────────────────────────────────────────────────────────


/** Extract a human-readable message from an unknown thrown value. */
function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

// ── Security & Audit Infrastructure ─────────────────────────────────────────

/** Security patterns for filesystem operations */
const PATH_TRAVERSAL_PATTERNS = [
  /\.\./,                                    // Directory traversal
  /[;&|`$(){}[\]\\]/,                       // Shell metacharacters in paths
  /\x00/,                                   // Null byte injection
  /[<>:"|*?]/,                              // Windows forbidden characters
  /(^|\/)\.\.($|\/)/,                       // Explicit .. directory references
];

/** Audit logger for filesystem security monitoring */
class FileSystemSecurityLogger {
  private static logDir = join(process.cwd(), 'logs');
  private static securityLogPath = join(FileSystemSecurityLogger.logDir, 'filesystem-bridge-security.log');

  static init() {
    if (!existsSync(FileSystemSecurityLogger.logDir)) {
      mkdirSync(FileSystemSecurityLogger.logDir, { recursive: true });
    }
  }

  static async logSecurityEvent(event: {
    type: 'PATH_BLOCKED' | 'FILE_OPERATION' | 'PATH_TRAVERSAL_DETECTED' | 'INPUT_VALIDATION_FAILED' | 'ACCESS_DENIED';
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    operation?: string;
    path?: string;
    reason: string;
    clientInfo?: string;
  }) {
    const logEntry = JSON.stringify({
      timestamp: new Date().toISOString(),
      level: event.severity,
      type: event.type,
      operation: event.operation || 'unknown',
      reason: event.reason,
      path_hash: event.path ? require('crypto').createHash('sha256').update(event.path).digest('hex').substring(0, 16) : undefined,
      client: event.clientInfo || 'unknown'
    }) + '\n';

    try {
      await appendFile(FileSystemSecurityLogger.securityLogPath, logEntry);
    } catch (error) {
      console.error('Failed to write filesystem security audit log:', error);
    }
  }
}

// Initialize filesystem security logger
FileSystemSecurityLogger.init();

/** Input validation schemas with security controls */
const FileSystemValidationSchemas = {
  readFile: z.object({
    filePath: z.string()
      .min(1, 'File path cannot be empty')
      .max(1000, 'File path too long (max 1000 characters)')
      .refine(
        (path) => !PATH_TRAVERSAL_PATTERNS.some(pattern => pattern.test(path)),
        'File path contains potentially dangerous patterns'
      ),
    offset: z.number().min(0).optional(),
    limit: z.number().min(1).max(100000).optional()
  }),

  writeFile: z.object({
    filePath: z.string()
      .min(1, 'File path cannot be empty')
      .max(1000, 'File path too long (max 1000 characters)')
      .refine(
        (path) => !PATH_TRAVERSAL_PATTERNS.some(pattern => pattern.test(path)),
        'File path contains potentially dangerous patterns'
      ),
    content: z.string()
      .max(50 * 1024 * 1024, 'Content too large (max 50MB)')
  }),

  editFile: z.object({
    filePath: z.string()
      .min(1, 'File path cannot be empty')
      .max(1000, 'File path too long (max 1000 characters)')
      .refine(
        (path) => !PATH_TRAVERSAL_PATTERNS.some(pattern => pattern.test(path)),
        'File path contains potentially dangerous patterns'
      ),
    oldString: z.string().max(10000, 'Old string too long'),
    newString: z.string().max(10000, 'New string too long'),
    replaceAll: z.boolean().optional()
  }),

  globSearch: z.object({
    pattern: z.string()
      .min(1, 'Pattern cannot be empty')
      .max(500, 'Pattern too long')
      .refine(
        (pattern) => !pattern.includes('..'),
        'Pattern cannot contain directory traversal'
      ),
    basePath: z.string()
      .max(1000, 'Base path too long')
      .refine(
        (path) => !PATH_TRAVERSAL_PATTERNS.some(pattern => pattern.test(path)),
        'Base path contains potentially dangerous patterns'
      )
      .optional()
  })
};

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

  /** Check if a path is within allowed paths using realpath (prevents path traversal). */
  private async isPathAllowed(filePath: string): Promise<{ allowed: boolean; reason?: string }> {
    try {
      // Resolve symlinks and get absolute path
      const realTarget = await realpath(filePath).catch(() => {
        // If realpath fails (file doesn't exist), resolve manually
        return resolve(filePath);
      });

      // Check each allowed path
      for (const allowedPath of this.config.allowedPaths) {
        try {
          const realAllowed = await realpath(allowedPath).catch(() => resolve(allowedPath));

          // Normalize paths for cross-platform comparison
          const normTarget = platform() === 'win32' ? realTarget.toLowerCase() : realTarget;
          const normAllowed = platform() === 'win32' ? realAllowed.toLowerCase() : realAllowed;

          // Check if target is within allowed directory boundary
          const isExact = normTarget === normAllowed;
          const isWithinDirectory = normTarget.startsWith(normAllowed + sep);

          if (isExact || isWithinDirectory) {
            return { allowed: true };
          }
        } catch (error) {
          // Log error resolving allowed path but continue checking others
          await FileSystemSecurityLogger.logSecurityEvent({
            type: 'INPUT_VALIDATION_FAILED',
            severity: 'MEDIUM',
            operation: 'path_validation',
            path: allowedPath,
            reason: `Error resolving allowed path: ${errorMessage(error)}`
          });
        }
      }

      // No allowed path matched
      await FileSystemSecurityLogger.logSecurityEvent({
        type: 'PATH_TRAVERSAL_DETECTED',
        severity: 'CRITICAL',
        operation: 'path_validation',
        path: filePath,
        reason: `Path ${filePath} (resolved to ${realTarget}) is not within any allowed paths: ${this.config.allowedPaths.join(', ')}`
      });

      return { allowed: false, reason: `Access denied: ${filePath} is not in allowed paths` };
    } catch (error) {
      await FileSystemSecurityLogger.logSecurityEvent({
        type: 'INPUT_VALIDATION_FAILED',
        severity: 'HIGH',
        operation: 'path_validation',
        path: filePath,
        reason: `Path validation failed: ${errorMessage(error)}`
      });

      return { allowed: false, reason: 'Path validation failed' };
    }
  }

  /** Read file contents with line numbers (like Claude Code's Read tool). */
  async readFile(filePath: string, offset?: number, limit?: number): Promise<string> {
    // Validate path with security checks
    const pathCheck = await this.isPathAllowed(filePath);
    if (!pathCheck.allowed) {
      throw new Error(pathCheck.reason || 'Access denied');
    }

    try {
      const content = await readFile(filePath, 'utf-8');
      const lines = content.split('\n');
      const startLine = offset || 0;
      const endLine = limit ? startLine + limit : lines.length;

      // Log successful file operation
      await FileSystemSecurityLogger.logSecurityEvent({
        type: 'FILE_OPERATION',
        severity: 'LOW',
        operation: 'read_file',
        path: filePath,
        reason: `File read successfully, lines ${startLine}-${endLine}`
      });

      return lines
        .slice(startLine, endLine)
        .map((line, index) => `${startLine + index + 1}\u2192${line}`)
        .join('\n');
    } catch (err) {
      await FileSystemSecurityLogger.logSecurityEvent({
        type: 'FILE_OPERATION',
        severity: 'MEDIUM',
        operation: 'read_file',
        path: filePath,
        reason: `File read failed: ${errorMessage(err)}`
      });
      throw new Error(`Failed to read file ${filePath}: ${errorMessage(err)}`);
    }
  }

  /** Write file contents, creating parent directories as needed. */
  async writeFile(filePath: string, content: string): Promise<string> {
    if (this.config.readOnly) {
      throw new Error('Write operations are disabled in read-only mode');
    }

    // Validate path with security checks
    const pathCheck = await this.isPathAllowed(filePath);
    if (!pathCheck.allowed) {
      throw new Error(pathCheck.reason || 'Access denied');
    }

    if (content.length > this.config.maxFileSize) {
      await FileSystemSecurityLogger.logSecurityEvent({
        type: 'INPUT_VALIDATION_FAILED',
        severity: 'HIGH',
        operation: 'write_file',
        path: filePath,
        reason: `File size ${content.length} exceeds maximum ${this.config.maxFileSize} bytes`
      });
      throw new Error(`File size exceeds maximum allowed size of ${this.config.maxFileSize} bytes`);
    }

    try {
      // Securely create parent directories with path validation
      const dir = dirname(resolve(filePath));
      const dirCheck = await this.isPathAllowed(dir);
      if (!dirCheck.allowed) {
        throw new Error('Cannot create parent directory outside allowed paths');
      }

      await mkdir(dir, { recursive: true });
      await writeFile(filePath, content, 'utf-8');

      // Log successful file operation
      await FileSystemSecurityLogger.logSecurityEvent({
        type: 'FILE_OPERATION',
        severity: 'LOW',
        operation: 'write_file',
        path: filePath,
        reason: `File written successfully, size: ${content.length} bytes`
      });

      return `File written successfully: ${filePath}`;
    } catch (err) {
      await FileSystemSecurityLogger.logSecurityEvent({
        type: 'FILE_OPERATION',
        severity: 'HIGH',
        operation: 'write_file',
        path: filePath,
        reason: `File write failed: ${errorMessage(err)}`
      });
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

    // Validate path with security checks
    const pathCheck = await this.isPathAllowed(filePath);
    if (!pathCheck.allowed) {
      throw new Error(pathCheck.reason || 'Access denied');
    }

    try {
      const content = await readFile(filePath, 'utf-8');
      let newContent: string;

      if (replaceAll) {
        newContent = content.replaceAll(oldString, newString);
      } else {
        const occurrences = content.split(oldString).length - 1;
        if (occurrences === 0) {
          await FileSystemSecurityLogger.logSecurityEvent({
            type: 'FILE_OPERATION',
            severity: 'MEDIUM',
            operation: 'edit_file',
            path: filePath,
            reason: `Edit failed: string not found`
          });
          throw new Error(`String not found: ${oldString}`);
        }
        if (occurrences > 1) {
          await FileSystemSecurityLogger.logSecurityEvent({
            type: 'FILE_OPERATION',
            severity: 'MEDIUM',
            operation: 'edit_file',
            path: filePath,
            reason: `Edit failed: non-unique string (${occurrences} occurrences)`
          });
          throw new Error(
            `String is not unique (found ${occurrences} occurrences). Use replaceAll=true or provide more context.`,
          );
        }
        newContent = content.replace(oldString, newString);
      }

      await writeFile(filePath, newContent, 'utf-8');

      // Log successful file operation
      await FileSystemSecurityLogger.logSecurityEvent({
        type: 'FILE_OPERATION',
        severity: 'LOW',
        operation: 'edit_file',
        path: filePath,
        reason: `File edited successfully, ${replaceAll ? 'replace all' : 'single replacement'}`
      });

      return `File edited successfully: ${filePath}`;
    } catch (err) {
      await FileSystemSecurityLogger.logSecurityEvent({
        type: 'FILE_OPERATION',
        severity: 'HIGH',
        operation: 'edit_file',
        path: filePath,
        reason: `File edit failed: ${errorMessage(err)}`
      });
      throw new Error(`Failed to edit file ${filePath}: ${errorMessage(err)}`);
    }
  }

  /** Find files by glob pattern. */
  async globSearch(pattern: string, basePath?: string): Promise<string[]> {
    // Determine search path with security validation
    let searchPath = this.config.allowedPaths[0];

    if (basePath) {
      const basePathCheck = await this.isPathAllowed(basePath);
      if (basePathCheck.allowed) {
        searchPath = basePath;
      } else {
        await FileSystemSecurityLogger.logSecurityEvent({
          type: 'PATH_BLOCKED',
          severity: 'HIGH',
          operation: 'glob_search',
          path: basePath,
          reason: `Base path not allowed, using default: ${basePathCheck.reason}`
        });
      }
    }

    try {
      const files = await glob(pattern, {
        cwd: searchPath,
        absolute: true,
        follow: false, // security: don't follow symlinks
      });

      // Filter files to ensure all results are within allowed paths
      const allowedFiles = [];
      for (const file of files) {
        const fileCheck = await this.isPathAllowed(file);
        if (fileCheck.allowed) {
          allowedFiles.push(file);
        }
      }

      // Log successful operation
      await FileSystemSecurityLogger.logSecurityEvent({
        type: 'FILE_OPERATION',
        severity: 'LOW',
        operation: 'glob_search',
        path: searchPath,
        reason: `Glob search completed, found ${allowedFiles.length} files matching pattern: ${pattern}`
      });

      return allowedFiles.map(file => relative(searchPath, file));
    } catch (err) {
      await FileSystemSecurityLogger.logSecurityEvent({
        type: 'FILE_OPERATION',
        severity: 'MEDIUM',
        operation: 'glob_search',
        path: searchPath,
        reason: `Glob search failed: ${errorMessage(err)}`
      });
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
        // Validate input with security schemas
        const validatedArgs = FileSystemValidationSchemas.readFile.parse(args);
        const { filePath, offset, limit } = validatedArgs;

        const result = await filesystem.readFile(filePath, offset, limit);
        return { content: [{ type: 'text', text: result }] };
      }

      case 'write_file': {
        // Validate input with security schemas
        const validatedArgs = FileSystemValidationSchemas.writeFile.parse(args);
        const { filePath, content } = validatedArgs;

        const result = await filesystem.writeFile(filePath, content);
        return { content: [{ type: 'text', text: result }] };
      }

      case 'edit_file': {
        // Validate input with security schemas
        const validatedArgs = FileSystemValidationSchemas.editFile.parse(args);
        const { filePath, oldString, newString, replaceAll } = validatedArgs;

        const result = await filesystem.editFile(filePath, oldString, newString, replaceAll);
        return { content: [{ type: 'text', text: result }] };
      }

      case 'glob_search': {
        // Validate input with security schemas
        const validatedArgs = FileSystemValidationSchemas.globSearch.parse(args);
        const { pattern, basePath } = validatedArgs;

        const files = await filesystem.globSearch(pattern, basePath);
        return { content: [{ type: 'text', text: files.length > 0 ? files.join('\n') : 'No files found' }] };
      }

      default:
        // Log unknown tool attempts for security analysis
        await FileSystemSecurityLogger.logSecurityEvent({
          type: 'INPUT_VALIDATION_FAILED',
          severity: 'MEDIUM',
          operation: 'unknown_tool',
          reason: `Unknown tool requested: ${name}`
        });
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (err) {
    // Log all tool execution errors for security analysis
    if (err instanceof z.ZodError) {
      // Input validation errors
      await FileSystemSecurityLogger.logSecurityEvent({
        type: 'INPUT_VALIDATION_FAILED',
        severity: 'HIGH',
        operation: name,
        reason: `Input validation failed for ${name}: ${err.errors.map(e => e.message).join(', ')}`
      });
    } else {
      // Other execution errors
      await FileSystemSecurityLogger.logSecurityEvent({
        type: 'FILE_OPERATION',
        severity: 'MEDIUM',
        operation: name,
        reason: `Tool execution failed for ${name}: ${errorMessage(err)}`
      });
    }

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
