#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from '@modelcontextprotocol/sdk/types.js';
import { spawn, exec } from 'child_process';
import { promisify } from 'util';
import { z } from 'zod';

const execAsync = promisify(exec);

// ── Helpers ──────────────────────────────────────────────────────────────────

/** Extract a human-readable message from an unknown thrown value. */
function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

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

  /** Check if a command is allowed to run. */
  private isCommandAllowed(command: string): boolean {
    const cmd = command.trim().split(/\s+/)[0].toLowerCase();

    if (this.config.blockedCommands.includes(cmd)) return false;

    if (this.config.allowedCommands && this.config.allowedCommands.length > 0) {
      return this.config.allowedCommands.includes(cmd);
    }

    return true;
  }

  /** Truncate output if it exceeds maximum size. */
  private truncateOutput(output: string): string {
    if (output.length <= this.config.maxOutputSize) return output;
    return `${output.substring(0, this.config.maxOutputSize)}\n\n... (output truncated, exceeded ${this.config.maxOutputSize} characters)`;
  }

  /** Execute a command (like Claude Code's Bash tool). */
  async runCommand(
    command: string,
    _description?: string,
  ): Promise<{ stdout: string; stderr: string; exitCode: number }> {
    if (!this.isCommandAllowed(command)) {
      throw new Error(`Command not allowed: ${command.split(/\s+/)[0]}`);
    }

    try {
      const { stdout, stderr } = await execAsync(command, {
        timeout: this.config.timeout,
        cwd: this.config.workingDirectory,
        maxBuffer: this.config.maxOutputSize * 2, // allow buffer headroom
      });

      return {
        stdout: this.truncateOutput(stdout || ''),
        stderr: this.truncateOutput(stderr || ''),
        exitCode: 0,
      };
    } catch (err: unknown) {
      // exec errors carry stdout/stderr/code on the error object
      const execErr = err as {
        stdout?: string; stderr?: string; message?: string;
        code?: number; signal?: string; killed?: boolean;
      };

      if (execErr.signal === 'SIGTERM' && execErr.killed) {
        throw new Error(`Command timed out after ${this.config.timeout}ms: ${command}`);
      }

      return {
        stdout: this.truncateOutput(execErr.stdout || ''),
        stderr: this.truncateOutput(execErr.stderr || execErr.message || ''),
        exitCode: typeof execErr.code === 'number' ? execErr.code : 1,
      };
    }
  }

  /** Start a background process. */
  async runBackground(command: string): Promise<{ taskId: string; message: string }> {
    if (!this.isCommandAllowed(command)) {
      throw new Error(`Command not allowed: ${command.split(/\s+/)[0]}`);
    }

    const taskId = `bg_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;

    try {
      const child = spawn(command, {
        shell: true,
        cwd: this.config.workingDirectory,
        detached: true,
        stdio: 'ignore',
      });
      child.unref();

      return {
        taskId,
        message: `Background task started with ID: ${taskId}. PID: ${child.pid}`,
      };
    } catch (err) {
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
        const { command, description } = args as { command: string; description?: string };
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
        const { command } = args as { command: string };
        const result = await shell.runBackground(command);
        return { content: [{ type: 'text', text: result.message }] };
      }

      case 'get_current_directory': {
        return { content: [{ type: 'text', text: shell.getCurrentDirectory() }] };
      }

      case 'change_directory': {
        const { path } = args as { path: string };
        const result = shell.changeDirectory(path);
        return { content: [{ type: 'text', text: result }] };
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
  console.error('Shell bridge MCP server running on stdio');
}

main().catch((err) => {
  console.error('Server failed to start:', err);
  process.exit(1);
});
