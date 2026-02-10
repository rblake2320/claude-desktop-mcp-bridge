#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from '@modelcontextprotocol/sdk/types.js';
import { spawn } from 'child_process';
import { z } from 'zod';
import { appendFile } from 'fs/promises';
import { existsSync, mkdirSync } from 'fs';
import { join } from 'path';
import { createHash } from 'node:crypto';

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Extract a human-readable message from an unknown thrown value. */
function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

// ── Security & Audit Infrastructure ─────────────────────────────────────────

/** Security patterns that indicate potential command injection */
const COMMAND_INJECTION_PATTERNS = [
  /[;&|`$(){}[\]\\]/,                    // Shell metacharacters
  /\n|\r/,                               // Line breaks
  /\.\./,                                // Directory traversal
  /\s+(rm|del|format|fdisk|mkfs|dd|shutdown|reboot|halt|poweroff)\s/i, // Dangerous commands
  /(^|\s)(sudo|su|chmod|chown|passwd)\s/i, // Privilege escalation
];

/** Audit logger for security monitoring */
class SecurityAuditLogger {
  private static logDir = join(process.cwd(), 'logs');
  private static securityLogPath = join(SecurityAuditLogger.logDir, 'shell-bridge-security.log');

  static init() {
    if (!existsSync(SecurityAuditLogger.logDir)) {
      mkdirSync(SecurityAuditLogger.logDir, { recursive: true });
    }
  }

  static async logSecurityEvent(event: {
    type: 'COMMAND_BLOCKED' | 'COMMAND_EXECUTED' | 'INPUT_VALIDATION_FAILED' | 'INJECTION_DETECTED';
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    command?: string;
    reason: string;
    clientInfo?: string;
  }) {
    const logEntry = JSON.stringify({
      timestamp: new Date().toISOString(),
      level: event.severity,
      type: event.type,
      reason: event.reason,
      command_hash: event.command ? createHash('sha256').update(event.command).digest('hex').substring(0, 16) : undefined,
      client: event.clientInfo || 'unknown'
    }) + '\n';

    try {
      await appendFile(SecurityAuditLogger.securityLogPath, logEntry);
    } catch (error) {
      console.error('Failed to write security audit log:', error);
    }
  }
}

// Initialize security logger
SecurityAuditLogger.init();

/** Input validation schemas with security controls */
const CommandValidationSchemas = {
  runCommand: z.object({
    command: z.string()
      .min(1, 'Command cannot be empty')
      .max(2000, 'Command too long (max 2000 characters)')
      .refine(
        (cmd) => !COMMAND_INJECTION_PATTERNS.some(pattern => pattern.test(cmd)),
        'Command contains potentially dangerous patterns'
      ),
    description: z.string()
      .max(500, 'Description too long')
      .optional()
  }),

  runBackground: z.object({
    command: z.string()
      .min(1, 'Command cannot be empty')
      .max(1000, 'Background command too long (max 1000 characters)')
      .refine(
        (cmd) => !COMMAND_INJECTION_PATTERNS.some(pattern => pattern.test(cmd)),
        'Command contains potentially dangerous patterns'
      )
  }),

  changeDirectory: z.object({
    path: z.string()
      .min(1, 'Path cannot be empty')
      .max(500, 'Path too long')
      .refine(
        (path) => !path.includes('..'),
        'Path traversal not allowed'
      )
      .refine(
        (path) => !/[;&|`$(){}[\]\\]/.test(path),
        'Path contains invalid characters'
      )
  })
};

// ── Configuration ────────────────────────────────────────────────────────────

const ConfigSchema = z.object({
  timeout: z.number().default(120_000), // 2 minutes
  maxOutputSize: z.number().default(30_000), // 30k chars (matches Claude Code)
  allowedCommands: z.array(z.string()).optional(),
  blockedCommands: z.array(z.string()).default([
    'rm', 'rmdir', 'del', 'format', 'fdisk', 'mkfs',
    'dd', 'shutdown', 'reboot', 'halt', 'poweroff',
  ]),
  workingDirectory: z.string().default(process.cwd()),
});

type Config = z.infer<typeof ConfigSchema>;

// ── Shell Bridge ─────────────────────────────────────────────────────────────

class ShellBridge {
  private config: Config;

  constructor(config: Partial<Config> = {}) {
    this.config = ConfigSchema.parse(config);
  }

  /** Parse command into program and arguments safely */
  private parseCommand(command: string): { program: string; args: string[] } {
    // Simple shell-style parsing (improved version would use a proper parser)
    const trimmed = command.trim();
    const parts = trimmed.split(/\s+/);

    return {
      program: parts[0],
      args: parts.slice(1)
    };
  }

  /** Check if a command is allowed to run with enhanced validation */
  private async isCommandAllowed(command: string): Promise<{ allowed: boolean; reason?: string }> {
    try {
      // Parse command to get base program
      const { program } = this.parseCommand(command);
      const baseCmd = program.toLowerCase();

      // Check blocked commands
      if (this.config.blockedCommands.includes(baseCmd)) {
        await SecurityAuditLogger.logSecurityEvent({
          type: 'COMMAND_BLOCKED',
          severity: 'HIGH',
          command,
          reason: `Command '${baseCmd}' is in blocked list`
        });
        return { allowed: false, reason: `Command '${baseCmd}' is not allowed` };
      }

      // Check allowed commands (if allowlist is configured)
      if (this.config.allowedCommands && this.config.allowedCommands.length > 0) {
        if (!this.config.allowedCommands.includes(baseCmd)) {
          await SecurityAuditLogger.logSecurityEvent({
            type: 'COMMAND_BLOCKED',
            severity: 'MEDIUM',
            command,
            reason: `Command '${baseCmd}' not in allowed list`
          });
          return { allowed: false, reason: `Command '${baseCmd}' is not in allowed list` };
        }
      }

      // Check for injection patterns
      for (const pattern of COMMAND_INJECTION_PATTERNS) {
        if (pattern.test(command)) {
          await SecurityAuditLogger.logSecurityEvent({
            type: 'INJECTION_DETECTED',
            severity: 'CRITICAL',
            command,
            reason: `Command contains injection pattern: ${pattern.source}`
          });
          return { allowed: false, reason: 'Command contains potentially dangerous patterns' };
        }
      }

      return { allowed: true };
    } catch (error) {
      await SecurityAuditLogger.logSecurityEvent({
        type: 'INPUT_VALIDATION_FAILED',
        severity: 'HIGH',
        command,
        reason: `Command validation failed: ${errorMessage(error)}`
      });
      return { allowed: false, reason: 'Command validation failed' };
    }
  }

  /** Truncate output if it exceeds maximum size. */
  private truncateOutput(output: string): string {
    if (output.length <= this.config.maxOutputSize) return output;
    return `${output.substring(0, this.config.maxOutputSize)}\n\n... (output truncated, exceeded ${this.config.maxOutputSize} characters)`;
  }

  /** Execute a command securely using spawn (no shell injection) */
  async runCommand(
    command: string,
    _description?: string,
  ): Promise<{ stdout: string; stderr: string; exitCode: number }> {
    // Pre-validation with enhanced security checks
    const validationResult = await this.isCommandAllowed(command);
    if (!validationResult.allowed) {
      throw new Error(validationResult.reason || 'Command not allowed');
    }

    try {
      // Parse command into program and arguments safely
      const { program, args } = this.parseCommand(command);

      // Use spawn with argument array (no shell=true to prevent injection)
      const result = await new Promise<{ stdout: string; stderr: string; exitCode: number }>((resolve, reject) => {
        const child = spawn(program, args, {
          cwd: this.config.workingDirectory,
          stdio: 'pipe',
          // CRITICAL: Never use shell: true here - it enables command injection
        });

        let stdout = '';
        let stderr = '';

        // Set up timeout
        const timeout = setTimeout(() => {
          child.kill('SIGTERM');
          reject(new Error(`Command timed out after ${this.config.timeout}ms`));
        }, this.config.timeout);

        // Collect output with size limits
        child.stdout?.on('data', (data) => {
          stdout += data.toString();
          if (stdout.length > this.config.maxOutputSize * 2) {
            child.kill('SIGTERM');
            reject(new Error('Output exceeded maximum size'));
          }
        });

        child.stderr?.on('data', (data) => {
          stderr += data.toString();
          if (stderr.length > this.config.maxOutputSize * 2) {
            child.kill('SIGTERM');
            reject(new Error('Error output exceeded maximum size'));
          }
        });

        child.on('close', (code) => {
          clearTimeout(timeout);
          resolve({
            stdout: this.truncateOutput(stdout),
            stderr: this.truncateOutput(stderr),
            exitCode: code || 0,
          });
        });

        child.on('error', (err) => {
          clearTimeout(timeout);
          reject(err);
        });
      });

      // Log successful execution
      await SecurityAuditLogger.logSecurityEvent({
        type: 'COMMAND_EXECUTED',
        severity: 'LOW',
        command,
        reason: `Command executed successfully with exit code ${result.exitCode}`
      });

      return result;
    } catch (err: unknown) {
      // Log failed execution
      await SecurityAuditLogger.logSecurityEvent({
        type: 'COMMAND_BLOCKED',
        severity: 'MEDIUM',
        command,
        reason: `Command execution failed: ${errorMessage(err)}`
      });

      // Handle specific error types
      const errorMsg = errorMessage(err);
      if (errorMsg.includes('timeout')) {
        throw new Error(`Command timed out after ${this.config.timeout}ms: ${command}`);
      }

      throw new Error(`Command execution failed: ${errorMsg}`);
    }
  }

  /** Start a background process securely (no shell injection) */
  async runBackground(command: string): Promise<{ taskId: string; message: string }> {
    // Pre-validation with enhanced security checks
    const validationResult = await this.isCommandAllowed(command);
    if (!validationResult.allowed) {
      throw new Error(validationResult.reason || 'Command not allowed');
    }

    const taskId = `bg_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;

    try {
      // Parse command into program and arguments safely
      const { program, args } = this.parseCommand(command);

      // Use spawn with argument array (no shell=true to prevent injection)
      const child = spawn(program, args, {
        cwd: this.config.workingDirectory,
        detached: true,
        stdio: 'ignore',
        // CRITICAL: Never use shell: true here - it enables command injection
      });
      child.unref();

      // Log background task start
      await SecurityAuditLogger.logSecurityEvent({
        type: 'COMMAND_EXECUTED',
        severity: 'LOW',
        command,
        reason: `Background task started with ID: ${taskId}, PID: ${child.pid}`
      });

      return {
        taskId,
        message: `Background task started with ID: ${taskId}. PID: ${child.pid}`,
      };
    } catch (err) {
      // Log failed background task
      await SecurityAuditLogger.logSecurityEvent({
        type: 'COMMAND_BLOCKED',
        severity: 'MEDIUM',
        command,
        reason: `Failed to start background task: ${errorMessage(err)}`
      });

      throw new Error(`Failed to start background task: ${errorMessage(err)}`);
    }
  }

  getCurrentDirectory(): string {
    return process.cwd();
  }

  changeDirectory(path: string): string {
    try {
      process.chdir(path);
      this.config.workingDirectory = process.cwd();
      return `Changed directory to: ${this.config.workingDirectory}`;
    } catch (err) {
      throw new Error(`Failed to change directory to ${path}: ${errorMessage(err)}`);
    }
  }
}

// ── Initialise ───────────────────────────────────────────────────────────────

const shell = new ShellBridge({
  timeout: process.env.TIMEOUT ? parseInt(process.env.TIMEOUT, 10) : undefined,
  allowedCommands: process.env.ALLOWED_COMMANDS?.split(','),
  blockedCommands: process.env.BLOCKED_COMMANDS?.split(','),
});

const server = new Server(
  { name: 'shell-bridge', version: '0.2.0' },
  { capabilities: { tools: {} } },
);

// ── Tool definitions ─────────────────────────────────────────────────────────

const tools: Tool[] = [
  {
    name: 'run_command',
    description: 'Execute a shell command (like Claude Code Bash tool)',
    inputSchema: {
      type: 'object',
      properties: {
        command: { type: 'string', description: 'The command to execute' },
        description: { type: 'string', description: 'Optional description of what the command does' },
      },
      required: ['command'],
    },
  },
  {
    name: 'run_background',
    description: 'Start a command in the background',
    inputSchema: {
      type: 'object',
      properties: {
        command: { type: 'string', description: 'The command to run in background' },
      },
      required: ['command'],
    },
  },
  {
    name: 'get_current_directory',
    description: 'Get the current working directory',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'change_directory',
    description: 'Change the current working directory',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Path to change to' },
      },
      required: ['path'],
    },
  },
];

// ── Handlers ─────────────────────────────────────────────────────────────────

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'run_command': {
        // Validate input with security schemas
        const validatedArgs = CommandValidationSchemas.runCommand.parse(args);
        const { command, description } = validatedArgs;

        const result = await shell.runCommand(command, description);

        let output = '';
        if (result.stdout) output += `STDOUT:\n${result.stdout}\n`;
        if (result.stderr) output += `STDERR:\n${result.stderr}\n`;
        output += `Exit Code: ${result.exitCode}`;

        return {
          content: [{ type: 'text', text: output }],
          isError: result.exitCode !== 0,
        };
      }

      case 'run_background': {
        // Validate input with security schemas
        const validatedArgs = CommandValidationSchemas.runBackground.parse(args);
        const { command } = validatedArgs;

        const result = await shell.runBackground(command);
        return { content: [{ type: 'text', text: result.message }] };
      }

      case 'get_current_directory': {
        return { content: [{ type: 'text', text: shell.getCurrentDirectory() }] };
      }

      case 'change_directory': {
        // Validate input with security schemas
        const validatedArgs = CommandValidationSchemas.changeDirectory.parse(args);
        const { path } = validatedArgs;

        const result = shell.changeDirectory(path);
        return { content: [{ type: 'text', text: result }] };
      }

      default:
        // Log unknown tool attempts
        await SecurityAuditLogger.logSecurityEvent({
          type: 'INPUT_VALIDATION_FAILED',
          severity: 'MEDIUM',
          reason: `Unknown tool requested: ${name}`
        });
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (err) {
    // Log all tool execution errors for security analysis
    if (err instanceof z.ZodError) {
      // Input validation errors
      await SecurityAuditLogger.logSecurityEvent({
        type: 'INPUT_VALIDATION_FAILED',
        severity: 'HIGH',
        reason: `Input validation failed for ${name}: ${err.errors.map(e => e.message).join(', ')}`
      });
    } else {
      // Other execution errors
      await SecurityAuditLogger.logSecurityEvent({
        type: 'COMMAND_BLOCKED',
        severity: 'MEDIUM',
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
  console.error('Shell bridge MCP server running on stdio');
}

main().catch((err) => {
  console.error('Server failed to start:', err);
  process.exit(1);
});
