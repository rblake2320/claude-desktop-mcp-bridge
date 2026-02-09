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

// Configuration schema
const ConfigSchema = z.object({
  timeout: z.number().default(120000), // 2 minutes default
  maxOutputSize: z.number().default(30000), // 30k characters like Claude Code
  allowedCommands: z.array(z.string()).optional(), // Whitelist of allowed commands
  blockedCommands: z.array(z.string()).default(['rm', 'rmdir', 'del', 'format', 'fdisk']), // Dangerous commands
  workingDirectory: z.string().default(process.cwd()),
});

type Config = z.infer<typeof ConfigSchema>;

class ShellBridge {
  private config: Config;

  constructor(config: Partial<Config> = {}) {
    this.config = ConfigSchema.parse(config);
  }

  /**
   * Check if a command is allowed to run
   */
  private isCommandAllowed(command: string): boolean {
    const cmd = command.trim().split(' ')[0].toLowerCase();

    // Check if command is explicitly blocked
    if (this.config.blockedCommands.includes(cmd)) {
      return false;
    }

    // If whitelist is defined, command must be in it
    if (this.config.allowedCommands && this.config.allowedCommands.length > 0) {
      return this.config.allowedCommands.includes(cmd);
    }

    return true;
  }

  /**
   * Truncate output if it exceeds maximum size
   */
  private truncateOutput(output: string): string {
    if (output.length <= this.config.maxOutputSize) {
      return output;
    }

    const truncated = output.substring(0, this.config.maxOutputSize);
    return `${truncated}\n\n... (output truncated, exceeded ${this.config.maxOutputSize} characters)`;
  }

  /**
   * Safe error message extraction
   */
  private getErrorMessage(error: unknown): string {
    if (error instanceof Error) {
      return error.message;
    }
    if (typeof error === 'string') {
      return error;
    }
    return String(error);
  }

  /**
   * Execute a command (like Claude Code's Bash tool)
   */
  async runCommand(command: string, description?: string): Promise<{ stdout: string; stderr: string; exitCode: number }> {
    if (!this.isCommandAllowed(command)) {
      throw new Error(`Command not allowed: ${command.split(' ')[0]}`);
    }

    try {
      const { stdout, stderr } = await execAsync(command, {
        timeout: this.config.timeout,
        cwd: this.config.workingDirectory,
        maxBuffer: this.config.maxOutputSize,
      });

      return {
        stdout: this.truncateOutput(stdout || ''),
        stderr: this.truncateOutput(stderr || ''),
        exitCode: 0,
      };
    } catch (error: any) {
      // Handle timeout and other execution errors
      const stdout = this.truncateOutput(error.stdout || '');
      const stderr = this.truncateOutput(error.stderr || this.getErrorMessage(error));
      const exitCode = error.code || 1;

      if (error.signal === 'SIGTERM' && error.killed) {
        throw new Error(`Command timed out after ${this.config.timeout}ms: ${command}`);
      }

      return { stdout, stderr, exitCode };
    }
  }

  /**
   * Start a background process (like Claude Code's run_in_background)
   */
  async runBackground(command: string): Promise<{ taskId: string; message: string }> {
    if (!this.isCommandAllowed(command)) {
      throw new Error(`Command not allowed: ${command.split(' ')[0]}`);
    }

    const taskId = `bg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    try {
      const child = spawn(command, {
        shell: true,
        cwd: this.config.workingDirectory,
        detached: true,
        stdio: 'ignore',
      });

      // Don't wait for the process
      child.unref();

      return {
        taskId,
        message: `Background task started with ID: ${taskId}. PID: ${child.pid}`,
      };
    } catch (error) {
      throw new Error(`Failed to start background task: ${this.getErrorMessage(error)}`);
    }
  }

  /**
   * Get current working directory
   */
  getCurrentDirectory(): string {
    return process.cwd();
  }

  /**
   * Change working directory
   */
  changeDirectory(path: string): string {
    try {
      process.chdir(path);
      this.config.workingDirectory = process.cwd();
      return `Changed directory to: ${this.config.workingDirectory}`;
    } catch (error) {
      throw new Error(`Failed to change directory to ${path}: ${this.getErrorMessage(error)}`);
    }
  }
}

// Initialize the shell bridge
const shell = new ShellBridge({
  timeout: process.env.TIMEOUT ? parseInt(process.env.TIMEOUT) : undefined,
  allowedCommands: process.env.ALLOWED_COMMANDS?.split(','),
  blockedCommands: process.env.BLOCKED_COMMANDS?.split(','),
});

// Create MCP server
const server = new Server(
  {
    name: 'shell-bridge',
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
    name: 'run_command',
    description: 'Execute a shell command (like Claude Code Bash tool)',
    inputSchema: {
      type: 'object',
      properties: {
        command: {
          type: 'string',
          description: 'The command to execute',
        },
        description: {
          type: 'string',
          description: 'Optional description of what the command does',
        },
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
        command: {
          type: 'string',
          description: 'The command to run in background',
        },
      },
      required: ['command'],
    },
  },
  {
    name: 'get_current_directory',
    description: 'Get the current working directory',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'change_directory',
    description: 'Change the current working directory',
    inputSchema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Path to change to',
        },
      },
      required: ['path'],
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
      case 'run_command': {
        const { command, description } = args as any;
        const result = await shell.runCommand(command, description);

        let output = '';
        if (result.stdout) output += `STDOUT:\n${result.stdout}\n`;
        if (result.stderr) output += `STDERR:\n${result.stderr}\n`;
        output += `Exit Code: ${result.exitCode}`;

        return {
          content: [
            {
              type: 'text',
              text: output,
            },
          ],
          isError: result.exitCode !== 0,
        };
      }

      case 'run_background': {
        const { command } = args as any;
        const result = await shell.runBackground(command);
        return {
          content: [
            {
              type: 'text',
              text: result.message,
            },
          ],
        };
      }

      case 'get_current_directory': {
        const cwd = shell.getCurrentDirectory();
        return {
          content: [
            {
              type: 'text',
              text: cwd,
            },
          ],
        };
      }

      case 'change_directory': {
        const { path } = args as any;
        const result = shell.changeDirectory(path);
        return {
          content: [
            {
              type: 'text',
              text: result,
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
          text: `Error: ${error instanceof Error ? error.message : String(error)}`,
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
  console.error('Shell bridge MCP server running on stdio');
}

main().catch((error) => {
  console.error('Server failed to start:', error);
  process.exit(1);
});