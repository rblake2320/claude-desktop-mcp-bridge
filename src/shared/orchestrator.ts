/**
 * Orchestrator - Execution engine for skills-bridge
 *
 * Turns skills from guidance-only into execution engines by coordinating
 * file operations and shell commands directly, without going through MCP.
 *
 * Security constraints match filesystem-bridge and shell-bridge:
 *  - Path validation via realpath against allowedPaths
 *  - Command validation against blockedCommands list
 *  - Shell metacharacter rejection
 *  - Timeout enforcement on shell operations
 *  - Max file size enforcement on writes
 *  - Audit logging of every operation to stderr
 */

import { readFile, writeFile, mkdir, realpath } from 'fs/promises';
import { spawn } from 'child_process';
import { dirname, resolve, sep } from 'path';
import { platform } from 'os';
import { glob } from 'glob';

// ── Public Types ────────────────────────────────────────────────────────────

export interface OrchestratorConfig {
  allowedPaths: string[];
  blockedCommands: string[];
  timeout: number;
  maxFileSize: number;
  readOnly: boolean;
}

export interface OrchestratorStep {
  name: string;
  type: 'read' | 'write' | 'edit' | 'shell' | 'glob';
  params: Record<string, any>;
  continueOnError?: boolean;
}

export interface StepResult {
  name: string;
  status: 'success' | 'error' | 'skipped';
  output?: string;
  error?: string;
  durationMs: number;
}

export interface OrchestratorResult {
  success: boolean;
  steps: StepResult[];
  totalDurationMs: number;
  summary: string;
}

// ── Internal Constants ──────────────────────────────────────────────────────

/** Characters that indicate shell metacharacter injection. */
const SHELL_METACHARACTERS = /[;&|`$(){}]/;

/** Whether we are running on Windows. */
const IS_WINDOWS = platform() === 'win32';

// ── Helpers ─────────────────────────────────────────────────────────────────

/** Extract a readable message from an unknown thrown value. */
function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

/** ISO-8601 timestamp for audit log entries. */
function timestamp(): string {
  return new Date().toISOString();
}

// ── Orchestrator Class ──────────────────────────────────────────────────────

export class Orchestrator {
  private config: OrchestratorConfig;

  constructor(config: OrchestratorConfig) {
    // Defensive copy so callers cannot mutate after construction.
    this.config = {
      allowedPaths: [...config.allowedPaths],
      blockedCommands: [...config.blockedCommands],
      timeout: config.timeout,
      maxFileSize: config.maxFileSize,
      readOnly: config.readOnly,
    };

    this.audit('INIT', `Orchestrator created: ${this.config.allowedPaths.length} allowed path(s), ` +
      `readOnly=${this.config.readOnly}, timeout=${this.config.timeout}ms`);
  }

  // ── File Operations ─────────────────────────────────────────────────────

  /**
   * Read a file after validating the path is within allowed directories.
   * Returns the raw file content as a UTF-8 string.
   */
  async readFile(filePath: string): Promise<string> {
    this.audit('READ_START', `Reading file: ${filePath}`);
    await this.validatePath(filePath);

    try {
      const content = await readFile(filePath, 'utf-8');
      this.audit('READ_OK', `Read ${content.length} bytes from ${filePath}`);
      return content;
    } catch (err) {
      this.audit('READ_FAIL', `Failed to read ${filePath}: ${errorMessage(err)}`);
      throw new Error(`Failed to read file ${filePath}: ${errorMessage(err)}`);
    }
  }

  /**
   * Write content to a file, creating parent directories as needed.
   * Enforces readOnly mode and maxFileSize.
   */
  async writeFile(filePath: string, content: string): Promise<string> {
    this.audit('WRITE_START', `Writing file: ${filePath} (${content.length} bytes)`);

    if (this.config.readOnly) {
      this.audit('WRITE_BLOCKED', `Write denied (readOnly mode): ${filePath}`);
      throw new Error('Write operations are disabled in read-only mode');
    }

    await this.validatePath(filePath);

    if (content.length > this.config.maxFileSize) {
      this.audit('WRITE_BLOCKED', `Content size ${content.length} exceeds max ${this.config.maxFileSize} for ${filePath}`);
      throw new Error(
        `Content size (${content.length} bytes) exceeds maximum allowed size (${this.config.maxFileSize} bytes)`,
      );
    }

    try {
      // Ensure parent directory exists and is within allowed paths.
      const dir = dirname(resolve(filePath));
      await this.validatePath(dir);
      await mkdir(dir, { recursive: true });

      await writeFile(filePath, content, 'utf-8');
      this.audit('WRITE_OK', `Wrote ${content.length} bytes to ${filePath}`);
      return `File written successfully: ${filePath}`;
    } catch (err) {
      // Re-throw our own validation errors without wrapping.
      if (err instanceof Error && (
        err.message.startsWith('Access denied') ||
        err.message.startsWith('Path validation failed') ||
        err.message.startsWith('Write operations are disabled') ||
        err.message.startsWith('Content size')
      )) {
        throw err;
      }
      this.audit('WRITE_FAIL', `Failed to write ${filePath}: ${errorMessage(err)}`);
      throw new Error(`Failed to write file ${filePath}: ${errorMessage(err)}`);
    }
  }

  /**
   * Edit a file by performing exact string replacement.
   * oldStr must appear exactly once in the file; otherwise the edit is rejected.
   */
  async editFile(filePath: string, oldStr: string, newStr: string): Promise<string> {
    this.audit('EDIT_START', `Editing file: ${filePath}`);

    if (this.config.readOnly) {
      this.audit('EDIT_BLOCKED', `Edit denied (readOnly mode): ${filePath}`);
      throw new Error('Edit operations are disabled in read-only mode');
    }

    await this.validatePath(filePath);

    try {
      const content = await readFile(filePath, 'utf-8');
      const occurrences = content.split(oldStr).length - 1;

      if (occurrences === 0) {
        this.audit('EDIT_FAIL', `Old string not found in ${filePath}`);
        throw new Error('Old string not found in file');
      }

      if (occurrences > 1) {
        this.audit('EDIT_FAIL', `Old string is not unique (${occurrences} occurrences) in ${filePath}`);
        throw new Error(
          `Old string is not unique (found ${occurrences} occurrences). Provide more context to make the match unique.`,
        );
      }

      const newContent = content.replace(oldStr, newStr);

      if (newContent.length > this.config.maxFileSize) {
        this.audit('EDIT_BLOCKED', `Resulting file size ${newContent.length} exceeds max ${this.config.maxFileSize}`);
        throw new Error(
          `Resulting file size (${newContent.length} bytes) exceeds maximum allowed size (${this.config.maxFileSize} bytes)`,
        );
      }

      await writeFile(filePath, newContent, 'utf-8');
      this.audit('EDIT_OK', `Edited ${filePath} successfully`);
      return `File edited successfully: ${filePath}`;
    } catch (err) {
      // Re-throw our own validation errors without wrapping.
      if (err instanceof Error && (
        err.message.startsWith('Access denied') ||
        err.message.startsWith('Path validation failed') ||
        err.message.startsWith('Edit operations are disabled') ||
        err.message.startsWith('Old string') ||
        err.message.startsWith('Resulting file size')
      )) {
        throw err;
      }
      this.audit('EDIT_FAIL', `Failed to edit ${filePath}: ${errorMessage(err)}`);
      throw new Error(`Failed to edit file ${filePath}: ${errorMessage(err)}`);
    }
  }

  /**
   * Search for files matching a glob pattern.
   * Results are filtered to only include paths within allowedPaths.
   */
  async globSearch(pattern: string, basePath?: string): Promise<string[]> {
    let searchBase = this.config.allowedPaths[0];

    if (basePath) {
      try {
        await this.validatePath(basePath);
        searchBase = basePath;
      } catch {
        this.audit('GLOB_PATH_DENIED', `Base path not allowed: ${basePath}, falling back to ${searchBase}`);
        // Fall through to default searchBase.
      }
    }

    this.audit('GLOB_START', `Glob search: pattern="${pattern}" base="${searchBase}"`);

    try {
      const files = await glob(pattern, {
        cwd: searchBase,
        absolute: true,
        follow: false,       // Security: do not follow symlinks.
      });

      // Filter results to paths within allowedPaths.
      const allowed: string[] = [];
      for (const file of files) {
        try {
          await this.validatePath(file);
          allowed.push(file);
        } catch {
          // Silently exclude files outside allowed paths.
        }
      }

      this.audit('GLOB_OK', `Found ${allowed.length} file(s) matching "${pattern}"`);
      return allowed;
    } catch (err) {
      this.audit('GLOB_FAIL', `Glob search failed: ${errorMessage(err)}`);
      throw new Error(`Glob search failed for pattern "${pattern}": ${errorMessage(err)}`);
    }
  }

  // ── Shell Operations ────────────────────────────────────────────────────

  /**
   * Execute a shell command and return structured output.
   * The command is validated against blockedCommands and shell metacharacters.
   * Execution is subject to the configured timeout.
   */
  async runCommand(
    command: string,
    cwd?: string,
  ): Promise<{ stdout: string; stderr: string; exitCode: number }> {
    this.audit('SHELL_START', `Running command: ${command}${cwd ? ` (cwd: ${cwd})` : ''}`);
    this.validateCommand(command);

    if (cwd) {
      await this.validatePath(cwd);
    }

    const workingDir = cwd || this.config.allowedPaths[0];

    return new Promise<{ stdout: string; stderr: string; exitCode: number }>((resolveP, rejectP) => {
      const parts = this.parseCommand(command);

      const child = spawn(parts.program, parts.args, {
        cwd: workingDir,
        stdio: 'pipe',
        shell: IS_WINDOWS,    // Required on Windows for .cmd wrappers and builtins.
      });

      let stdout = '';
      let stderr = '';
      let settled = false;

      const timeoutId = setTimeout(() => {
        if (!settled) {
          settled = true;
          child.kill('SIGTERM');
          this.audit('SHELL_TIMEOUT', `Command timed out after ${this.config.timeout}ms: ${command}`);
          rejectP(new Error(`Command timed out after ${this.config.timeout}ms`));
        }
      }, this.config.timeout);

      child.stdout?.on('data', (data: Buffer) => {
        stdout += data.toString();
      });

      child.stderr?.on('data', (data: Buffer) => {
        stderr += data.toString();
      });

      child.on('close', (code: number | null) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeoutId);

        const exitCode = code ?? 0;
        this.audit('SHELL_OK', `Command exited with code ${exitCode}: ${command}`);
        resolveP({ stdout, stderr, exitCode });
      });

      child.on('error', (err: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeoutId);

        this.audit('SHELL_FAIL', `Command spawn error: ${err.message}`);
        rejectP(new Error(`Failed to execute command: ${err.message}`));
      });
    });
  }

  /**
   * Execute a command and return combined output as a single string.
   * Throws if the command exits with a non-zero code.
   */
  async runCommandSafe(command: string, cwd?: string): Promise<string> {
    const result = await this.runCommand(command, cwd);

    const combined = [result.stdout, result.stderr]
      .filter(Boolean)
      .join('\n')
      .trim();

    if (result.exitCode !== 0) {
      throw new Error(
        `Command failed with exit code ${result.exitCode}: ${combined || '(no output)'}`,
      );
    }

    return combined;
  }

  // ── Orchestration ───────────────────────────────────────────────────────

  /**
   * Execute a sequence of orchestrator steps, collecting results.
   * Steps run sequentially. If a step fails and continueOnError is false
   * (the default), remaining steps are skipped.
   */
  async executeSteps(steps: OrchestratorStep[]): Promise<OrchestratorResult> {
    const overallStart = Date.now();
    const results: StepResult[] = [];
    let aborted = false;

    this.audit('ORCHESTRATE_START', `Executing ${steps.length} step(s)`);

    for (const step of steps) {
      if (aborted) {
        results.push({
          name: step.name,
          status: 'skipped',
          error: 'Skipped due to previous step failure',
          durationMs: 0,
        });
        continue;
      }

      const stepStart = Date.now();

      try {
        const output = await this.executeStep(step);
        results.push({
          name: step.name,
          status: 'success',
          output,
          durationMs: Date.now() - stepStart,
        });
      } catch (err) {
        const errMsg = errorMessage(err);
        results.push({
          name: step.name,
          status: 'error',
          error: errMsg,
          durationMs: Date.now() - stepStart,
        });

        if (!step.continueOnError) {
          aborted = true;
        }
      }
    }

    const totalDurationMs = Date.now() - overallStart;

    const succeeded = results.filter(r => r.status === 'success').length;
    const failed = results.filter(r => r.status === 'error').length;
    const skipped = results.filter(r => r.status === 'skipped').length;

    const success = failed === 0;
    const summary = `Executed ${steps.length} step(s) in ${totalDurationMs}ms: ` +
      `${succeeded} succeeded, ${failed} failed, ${skipped} skipped`;

    this.audit('ORCHESTRATE_DONE', summary);

    return { success, steps: results, totalDurationMs, summary };
  }

  // ── Private: Step Dispatch ──────────────────────────────────────────────

  private async executeStep(step: OrchestratorStep): Promise<string> {
    const params = step.params;

    switch (step.type) {
      case 'read': {
        const filePath = this.requireParam<string>(params, 'filePath', step.name);
        return await this.readFile(filePath);
      }

      case 'write': {
        const filePath = this.requireParam<string>(params, 'filePath', step.name);
        const content = this.requireParam<string>(params, 'content', step.name);
        return await this.writeFile(filePath, content);
      }

      case 'edit': {
        const filePath = this.requireParam<string>(params, 'filePath', step.name);
        const oldStr = this.requireParam<string>(params, 'oldString', step.name);
        const newStr = this.requireParam<string>(params, 'newString', step.name);
        return await this.editFile(filePath, oldStr, newStr);
      }

      case 'shell': {
        const command = this.requireParam<string>(params, 'command', step.name);
        const cwd = params['cwd'] as string | undefined;
        return await this.runCommandSafe(command, cwd);
      }

      case 'glob': {
        const pattern = this.requireParam<string>(params, 'pattern', step.name);
        const basePath = params['basePath'] as string | undefined;
        const files = await this.globSearch(pattern, basePath);
        return files.length > 0 ? files.join('\n') : 'No files found';
      }

      default:
        throw new Error(`Unknown step type: ${(step as OrchestratorStep).type}`);
    }
  }

  /**
   * Extract a required parameter from a step's params, throwing a clear
   * error when missing.
   */
  private requireParam<T>(params: Record<string, any>, key: string, stepName: string): T {
    if (!(key in params) || params[key] === undefined || params[key] === null) {
      throw new Error(`Step "${stepName}" is missing required parameter "${key}"`);
    }
    return params[key] as T;
  }

  // ── Private: Security Validation ────────────────────────────────────────

  /**
   * Validate that a file/directory path is within the configured allowedPaths.
   * Uses realpath to resolve symlinks and prevent traversal attacks.
   */
  private async validatePath(targetPath: string): Promise<void> {
    let resolvedTarget: string;
    try {
      // Attempt realpath first (resolves symlinks). Falls back to resolve()
      // for paths that do not yet exist (e.g. new file to be written).
      resolvedTarget = await realpath(targetPath).catch(() => resolve(targetPath));
    } catch {
      resolvedTarget = resolve(targetPath);
    }

    for (const allowedPath of this.config.allowedPaths) {
      let resolvedAllowed: string;
      try {
        resolvedAllowed = await realpath(allowedPath).catch(() => resolve(allowedPath));
      } catch {
        resolvedAllowed = resolve(allowedPath);
      }

      // Normalise for case-insensitive comparison on Windows.
      const normTarget = IS_WINDOWS ? resolvedTarget.toLowerCase() : resolvedTarget;
      const normAllowed = IS_WINDOWS ? resolvedAllowed.toLowerCase() : resolvedAllowed;

      const isExact = normTarget === normAllowed;
      const isChild = normTarget.startsWith(normAllowed + sep);

      if (isExact || isChild) {
        return; // Path is within an allowed directory.
      }
    }

    this.audit('PATH_DENIED', `Access denied: ${targetPath} is not within allowed paths`);
    throw new Error(`Access denied: ${targetPath} is not within allowed paths`);
  }

  /**
   * Validate a command string:
   *  1. Not empty
   *  2. No shell metacharacters
   *  3. Base program not in blockedCommands
   */
  private validateCommand(command: string): void {
    if (!command || command.trim().length === 0) {
      this.audit('CMD_BLOCKED', 'Empty command rejected');
      throw new Error('Command cannot be empty');
    }

    // Check for shell metacharacters that could enable injection.
    if (SHELL_METACHARACTERS.test(command)) {
      this.audit('CMD_BLOCKED', `Shell metacharacters detected in command: ${command}`);
      throw new Error(
        'Command contains disallowed shell metacharacters. ' +
        'Characters ; & | ` $ ( ) { } are not permitted.',
      );
    }

    // Extract the base program name and check against the blocked list.
    const { program } = this.parseCommand(command);
    const baseCmd = program.toLowerCase();

    if (this.config.blockedCommands.some(blocked => blocked.toLowerCase() === baseCmd)) {
      this.audit('CMD_BLOCKED', `Blocked command rejected: ${baseCmd}`);
      throw new Error(`Command "${baseCmd}" is not allowed`);
    }
  }

  /**
   * Split a command string into program + arguments.
   * Handles simple space-separated tokens (no quote parsing; the
   * metacharacter check above prevents shell tricks).
   */
  private parseCommand(command: string): { program: string; args: string[] } {
    const trimmed = command.trim();
    const parts = trimmed.split(/\s+/);
    return {
      program: parts[0],
      args: parts.slice(1),
    };
  }

  // ── Private: Audit Logging ──────────────────────────────────────────────

  /**
   * Write a structured audit entry to stderr.
   * Matches the project convention of using console.error for MCP server
   * diagnostics and security events.
   */
  private audit(event: string, message: string): void {
    console.error(
      JSON.stringify({
        ts: timestamp(),
        src: 'orchestrator',
        event,
        msg: message,
      }),
    );
  }
}
