/**
 * Persistent state management module for cross-bridge coordination.
 *
 * Provides a singleton StateManager that persists namespaced key-value state,
 * skill usage analytics, bridge health records, and orchestration task history
 * across Claude Desktop restarts.
 *
 * State is stored as JSON in `data/bridge-state.json` relative to the project
 * root (resolved via import.meta.url).  Falls back to
 * %TEMP%/claude-mcp-bridge-data/ when the project directory is not writable.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync, unlinkSync } from 'fs';
import { dirname, join } from 'path';
import { randomUUID } from 'crypto';
import { fileURLToPath } from 'url';

// ── Types ────────────────────────────────────────────────────────────────────

export interface SkillUsageRecord {
  skillName: string;
  input: string;
  success: boolean;
  durationMs: number;
  timestamp: string;
}

export interface SkillUsageStats {
  totalInvocations: number;
  successRate: number;
  avgDurationMs: number;
  uniqueSkillsUsed: number;
  mostUsed: string;
  lastUsed: string;
}

export interface BridgeHealthRecord {
  bridgeName: string;
  status: 'healthy' | 'degraded' | 'error';
  lastCheck: string;
  details?: string;
  uptime: number; // seconds since last healthy state
}

export interface TaskRecord {
  id: string;
  name: string;
  status: 'pending' | 'running' | 'success' | 'failure';
  steps: Array<{ name: string; status: string; output?: string }>;
  startedAt: string;
  completedAt?: string;
  output?: string;
}

export interface StateData {
  version: number;
  sessionId: string;
  sessionStarted: string;
  namespaces: Record<string, Record<string, unknown>>;
  skillUsage: SkillUsageRecord[];
  bridgeHealth: Record<string, BridgeHealthRecord>;
  tasks: TaskRecord[];
}

// ── Constants ────────────────────────────────────────────────────────────────

const STATE_VERSION = 1;
const MAX_SKILL_USAGE_RECORDS = 1000;
const MAX_TASK_RECORDS = 100;
const DEBOUNCE_MS = 1000;
const STATE_FILENAME = 'bridge-state.json';

// ── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Resolve the `data/` directory for state persistence.
 *
 * Primary: <project-root>/data/  (two directories up from src/shared/)
 * Fallback: %TEMP%/claude-mcp-bridge-data/
 */
function resolveDataDir(): string {
  try {
    const thisFile = fileURLToPath(import.meta.url);
    const thisDir = dirname(thisFile);
    // src/shared -> src -> project root
    const projectRoot = join(thisDir, '..', '..');
    const dataDir = join(projectRoot, 'data');

    if (!existsSync(dataDir)) {
      mkdirSync(dataDir, { recursive: true });
    }

    // Verify write access by touching a probe file
    const probe = join(dataDir, '.write-probe');
    writeFileSync(probe, '', 'utf-8');
    // Clean up probe — ignore errors
    try {
      unlinkSync(probe);
    } catch {
      // Probe cleanup is best-effort
    }

    return dataDir;
  } catch {
    // Fallback to temp directory
    const tempBase = process.env.TEMP || process.env.TMP || '/tmp';
    const fallbackDir = join(tempBase, 'claude-mcp-bridge-data');
    if (!existsSync(fallbackDir)) {
      mkdirSync(fallbackDir, { recursive: true });
    }
    return fallbackDir;
  }
}

/** Create a blank state object with a fresh session. */
function createEmptyState(): StateData {
  return {
    version: STATE_VERSION,
    sessionId: randomUUID(),
    sessionStarted: new Date().toISOString(),
    namespaces: {},
    skillUsage: [],
    bridgeHealth: {},
    tasks: [],
  };
}

// ── StateManager ─────────────────────────────────────────────────────────────

export class StateManager {
  // Singleton
  private static instance: StateManager | null = null;

  private state: StateData;
  private readonly statePath: string;
  private saveTimer: ReturnType<typeof setTimeout> | null = null;
  private savePending = false;

  private constructor() {
    const dataDir = resolveDataDir();
    this.statePath = join(dataDir, STATE_FILENAME);
    this.state = createEmptyState();
    this.load();
  }

  /** Return the singleton StateManager instance. */
  static getInstance(): StateManager {
    if (!StateManager.instance) {
      StateManager.instance = new StateManager();
    }
    return StateManager.instance;
  }

  // ── Session management ───────────────────────────────────────────────────

  /** Return the current session identifier. */
  getSessionId(): string {
    return this.state.sessionId;
  }

  /** Start a new session, generating a fresh session ID and timestamp. */
  startSession(): void {
    this.state.sessionId = randomUUID();
    this.state.sessionStarted = new Date().toISOString();
    this.scheduleSave();
  }

  /** End the current session (persists final state). */
  endSession(): void {
    this.flushSave();
  }

  // ── Key-value state (namespaced) ─────────────────────────────────────────

  /** Retrieve a value from a namespace. Returns `defaultValue` when absent. */
  get<T>(namespace: string, key: string, defaultValue?: T): T | undefined {
    const ns = this.state.namespaces[namespace];
    if (!ns || !(key in ns)) {
      return defaultValue;
    }
    return ns[key] as T;
  }

  /** Set a value in a namespace. Creates the namespace if it does not exist. */
  set<T>(namespace: string, key: string, value: T): void {
    if (!this.state.namespaces[namespace]) {
      this.state.namespaces[namespace] = {};
    }
    this.state.namespaces[namespace][key] = value;
    this.scheduleSave();
  }

  /** Delete a single key from a namespace. */
  delete(namespace: string, key: string): void {
    const ns = this.state.namespaces[namespace];
    if (ns) {
      delete ns[key];
      // Remove the namespace entirely if empty
      if (Object.keys(ns).length === 0) {
        delete this.state.namespaces[namespace];
      }
      this.scheduleSave();
    }
  }

  /** Return a shallow copy of all key-value pairs in a namespace. */
  getNamespace(namespace: string): Record<string, unknown> {
    return { ...(this.state.namespaces[namespace] ?? {}) };
  }

  // ── Skill usage tracking ─────────────────────────────────────────────────

  /** Record a skill invocation for analytics. */
  recordSkillUsage(
    skillName: string,
    input: string,
    success: boolean,
    durationMs: number,
  ): void {
    const record: SkillUsageRecord = {
      skillName,
      input: input.length > 500 ? input.slice(0, 500) + '...' : input,
      success,
      durationMs,
      timestamp: new Date().toISOString(),
    };

    this.state.skillUsage.push(record);

    // FIFO: keep only the most recent records
    if (this.state.skillUsage.length > MAX_SKILL_USAGE_RECORDS) {
      this.state.skillUsage = this.state.skillUsage.slice(
        this.state.skillUsage.length - MAX_SKILL_USAGE_RECORDS,
      );
    }

    this.scheduleSave();
  }

  /** Compute aggregate statistics over all recorded skill usage. */
  getSkillUsageStats(): SkillUsageStats {
    const records = this.state.skillUsage;
    if (records.length === 0) {
      return {
        totalInvocations: 0,
        successRate: 0,
        avgDurationMs: 0,
        uniqueSkillsUsed: 0,
        mostUsed: '',
        lastUsed: '',
      };
    }

    const successCount = records.filter((r) => r.success).length;
    const totalDuration = records.reduce((sum, r) => sum + r.durationMs, 0);
    const skillNames = new Set(records.map((r) => r.skillName));

    // Determine most-used skill
    const counts = new Map<string, number>();
    for (const r of records) {
      counts.set(r.skillName, (counts.get(r.skillName) ?? 0) + 1);
    }
    let mostUsed = '';
    let maxCount = 0;
    for (const [name, count] of counts) {
      if (count > maxCount) {
        maxCount = count;
        mostUsed = name;
      }
    }

    return {
      totalInvocations: records.length,
      successRate: successCount / records.length,
      avgDurationMs: Math.round(totalDuration / records.length),
      uniqueSkillsUsed: skillNames.size,
      mostUsed,
      lastUsed: records[records.length - 1].timestamp,
    };
  }

  /** Return the N most recent skill usage records. */
  getRecentSkills(limit = 10): SkillUsageRecord[] {
    return this.state.skillUsage.slice(-limit);
  }

  /** Return skills ranked by invocation count with average duration. */
  getMostUsedSkills(
    limit = 10,
  ): Array<{ name: string; count: number; avgDurationMs: number }> {
    const agg = new Map<string, { total: number; duration: number }>();

    for (const r of this.state.skillUsage) {
      const entry = agg.get(r.skillName) ?? { total: 0, duration: 0 };
      entry.total += 1;
      entry.duration += r.durationMs;
      agg.set(r.skillName, entry);
    }

    const sorted = [...agg.entries()]
      .map(([name, { total, duration }]) => ({
        name,
        count: total,
        avgDurationMs: Math.round(duration / total),
      }))
      .sort((a, b) => b.count - a.count);

    return sorted.slice(0, limit);
  }

  // ── Bridge health tracking ───────────────────────────────────────────────

  /** Record a health check for a bridge. */
  recordBridgeHealth(
    bridgeName: string,
    status: 'healthy' | 'degraded' | 'error',
    details?: string,
  ): void {
    const now = new Date();
    const existing = this.state.bridgeHealth[bridgeName];

    let uptime = 0;
    if (existing) {
      if (status === 'healthy') {
        // If previously healthy, continue uptime; otherwise reset
        if (existing.status === 'healthy') {
          const lastCheckTime = new Date(existing.lastCheck).getTime();
          uptime = existing.uptime + Math.round((now.getTime() - lastCheckTime) / 1000);
        }
        // If recovering from degraded/error, uptime resets to 0
      } else {
        // Non-healthy: preserve existing uptime (frozen since last healthy)
        uptime = existing.uptime;
      }
    }

    this.state.bridgeHealth[bridgeName] = {
      bridgeName,
      status,
      lastCheck: now.toISOString(),
      details,
      uptime,
    };

    this.scheduleSave();
  }

  /** Return the latest health record for every known bridge. */
  getBridgeHealth(): Record<string, BridgeHealthRecord> {
    // Return a defensive copy
    const result: Record<string, BridgeHealthRecord> = {};
    for (const [key, value] of Object.entries(this.state.bridgeHealth)) {
      result[key] = { ...value };
    }
    return result;
  }

  // ── Orchestration task tracking ──────────────────────────────────────────

  /** Record a new or updated task. */
  recordTask(task: TaskRecord): void {
    const idx = this.state.tasks.findIndex((t) => t.id === task.id);
    if (idx >= 0) {
      this.state.tasks[idx] = task;
    } else {
      this.state.tasks.push(task);
    }

    // FIFO: keep only the most recent tasks
    if (this.state.tasks.length > MAX_TASK_RECORDS) {
      // Remove oldest completed tasks first, then oldest overall
      const completed = this.state.tasks
        .map((t, i) => ({ t, i }))
        .filter(({ t }) => t.status === 'success' || t.status === 'failure')
        .map(({ i }) => i);

      if (completed.length > 0) {
        this.state.tasks.splice(completed[0], 1);
      } else {
        this.state.tasks.shift();
      }
    }

    this.scheduleSave();
  }

  /** Return all tasks with status 'pending' or 'running'. */
  getActiveTasks(): TaskRecord[] {
    return this.state.tasks.filter(
      (t) => t.status === 'pending' || t.status === 'running',
    );
  }

  /** Mark a task as complete (success or failure). */
  completeTask(
    taskId: string,
    result: 'success' | 'failure',
    output?: string,
  ): void {
    const task = this.state.tasks.find((t) => t.id === taskId);
    if (task) {
      task.status = result;
      task.completedAt = new Date().toISOString();
      if (output !== undefined) {
        task.output = output;
      }
      this.scheduleSave();
    }
  }

  // ── Persistence ──────────────────────────────────────────────────────────

  /** Load state from disk. Initialises a fresh session if no file exists. */
  load(): void {
    try {
      if (existsSync(this.statePath)) {
        const raw = readFileSync(this.statePath, 'utf-8');
        const parsed = JSON.parse(raw) as Partial<StateData>;

        // Validate version compatibility
        if (parsed.version === STATE_VERSION) {
          this.state = {
            version: STATE_VERSION,
            sessionId: parsed.sessionId ?? randomUUID(),
            sessionStarted: parsed.sessionStarted ?? new Date().toISOString(),
            namespaces: parsed.namespaces ?? {},
            skillUsage: Array.isArray(parsed.skillUsage) ? parsed.skillUsage : [],
            bridgeHealth: parsed.bridgeHealth ?? {},
            tasks: Array.isArray(parsed.tasks) ? parsed.tasks : [],
          };
        } else {
          // Version mismatch — start fresh but preserve namespaces if possible
          console.error(
            `[StateManager] State version mismatch (file=${parsed.version}, expected=${STATE_VERSION}). Starting fresh session.`,
          );
          const fresh = createEmptyState();
          if (parsed.namespaces && typeof parsed.namespaces === 'object') {
            fresh.namespaces = parsed.namespaces;
          }
          this.state = fresh;
        }

        // Enforce limits on loaded data
        if (this.state.skillUsage.length > MAX_SKILL_USAGE_RECORDS) {
          this.state.skillUsage = this.state.skillUsage.slice(
            this.state.skillUsage.length - MAX_SKILL_USAGE_RECORDS,
          );
        }
        if (this.state.tasks.length > MAX_TASK_RECORDS) {
          this.state.tasks = this.state.tasks.slice(
            this.state.tasks.length - MAX_TASK_RECORDS,
          );
        }
      } else {
        // No existing state file — keep the fresh state from constructor
        this.save();
      }
    } catch (err) {
      console.error(
        `[StateManager] Failed to load state from ${this.statePath}:`,
        err instanceof Error ? err.message : String(err),
      );
      // Keep the fresh state already assigned in constructor
    }
  }

  /** Immediately persist the current state to disk. */
  save(): void {
    this.cancelPendingSave();
    this.writeToDisk();
  }

  // ── Internal persistence helpers ─────────────────────────────────────────

  /** Schedule a debounced save (max one write per DEBOUNCE_MS). */
  private scheduleSave(): void {
    if (this.saveTimer) {
      // A save is already scheduled — just mark that another mutation happened
      this.savePending = true;
      return;
    }

    this.saveTimer = setTimeout(() => {
      this.writeToDisk();
      this.saveTimer = null;

      // If additional mutations arrived while we were waiting, save again
      if (this.savePending) {
        this.savePending = false;
        this.scheduleSave();
      }
    }, DEBOUNCE_MS);
  }

  /** Cancel any pending debounced save. */
  private cancelPendingSave(): void {
    if (this.saveTimer) {
      clearTimeout(this.saveTimer);
      this.saveTimer = null;
    }
    this.savePending = false;
  }

  /** Flush: if a save is pending, write immediately. */
  private flushSave(): void {
    if (this.saveTimer || this.savePending) {
      this.cancelPendingSave();
      this.writeToDisk();
    }
  }

  /** Write the state JSON to disk. Errors are logged but never thrown. */
  private writeToDisk(): void {
    try {
      const dir = dirname(this.statePath);
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
      }

      const json = JSON.stringify(this.state, null, 2);
      writeFileSync(this.statePath, json, 'utf-8');
    } catch (err) {
      console.error(
        `[StateManager] Failed to save state to ${this.statePath}:`,
        err instanceof Error ? err.message : String(err),
      );
    }
  }
}
