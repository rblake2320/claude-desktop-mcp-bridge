/**
 * MCP Protocol Handler
 *
 * Handles protocol version detection, capability negotiation, and message
 * formatting for both Claude Desktop Classic (2024-11-05) and Claude Desktop
 * with Cowork (2025-06-18). Provides a single abstraction layer so bridge
 * servers can emit notifications, advertise capabilities, and format responses
 * without branching on protocol versions throughout their code.
 */

// ── Known protocol versions ──────────────────────────────────────────────────

const PROTOCOL_CLASSIC = '2024-11-05' as const;
const PROTOCOL_COWORK = '2025-06-18' as const;

const UI_EXTENSION_KEY = 'io.modelcontextprotocol/ui';
const HTML_MIME_TYPE = 'text/html;profile=mcp-app';

// ── Public types ─────────────────────────────────────────────────────────────

export type ProtocolVersion = typeof PROTOCOL_CLASSIC | typeof PROTOCOL_COWORK | string;

export interface ProtocolInfo {
  version: string;
  isCowork: boolean;
  hasUI: boolean;
  clientName: string;
  clientVersion: string;
  extensions: Record<string, unknown>;
  compatibilityNotes: string[];
}

export interface ClientInfo {
  name: string;
  version: string;
  protocolVersion: string;
}

export interface ServerCapabilities {
  tools: Record<string, never>;
  resources?: { subscribe?: boolean; listChanged?: boolean };
  prompts?: { listChanged?: boolean };
  logging?: Record<string, never>;
  experimental?: Record<string, unknown>;
}

export interface ContentBlock {
  type: string;
  text: string;
  mimeType?: string;
}

export interface ResponseOptions {
  useHTML?: boolean;
  mimeType?: string;
  isError?: boolean;
}

export interface ToolResponse {
  content: ContentBlock[];
  isError?: boolean;
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/**
 * Compare two ISO-date-style version strings lexicographically.
 * Returns a positive number when `a` is newer than `b`.
 */
function compareVersionStrings(a: string, b: string): number {
  // Strip anything that is not a digit or hyphen so the comparison is safe
  // against unexpected suffixes.
  const normalize = (v: string) => v.replace(/[^\d-]/g, '');
  return normalize(a).localeCompare(normalize(b));
}

/**
 * Walk an arbitrary nested object with a dot-separated key path.
 * Returns `undefined` when any segment is missing.
 */
function getNestedValue(obj: unknown, path: string): unknown {
  let current: unknown = obj;
  for (const segment of path.split('.')) {
    if (current === null || current === undefined || typeof current !== 'object') {
      return undefined;
    }
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}

// ── ProtocolHandler ──────────────────────────────────────────────────────────

export class ProtocolHandler {
  private protocolVersion: string = PROTOCOL_CLASSIC;
  private clientName: string = 'unknown';
  private clientVersion: string = 'unknown';
  private extensions: Record<string, unknown> = {};
  private capabilities: Record<string, unknown> = {};
  private coworkEnabled: boolean = false;
  private uiExtensionAvailable: boolean = false;
  private supportedMimeTypes: string[] = [];
  private notes: string[] = [];

  // ── Protocol version detection ───────────────────────────────────────────

  /**
   * Inspect the `initialize` request parameters sent by the client and
   * extract everything we need to know about the connected host.
   *
   * This method should be called exactly once, during the MCP `initialize`
   * handshake. Subsequent calls will overwrite prior state.
   */
  detectProtocolVersion(initializeParams: unknown): ProtocolInfo {
    const params = (initializeParams ?? {}) as Record<string, unknown>;

    // -- protocol version -------------------------------------------------
    this.protocolVersion =
      typeof params.protocolVersion === 'string'
        ? params.protocolVersion
        : PROTOCOL_CLASSIC;

    // -- client info ------------------------------------------------------
    const rawClientInfo = params.clientInfo as Record<string, unknown> | undefined;
    this.clientName = typeof rawClientInfo?.name === 'string' ? rawClientInfo.name : 'unknown';
    this.clientVersion = typeof rawClientInfo?.version === 'string' ? rawClientInfo.version : 'unknown';

    // -- capabilities & extensions ----------------------------------------
    this.capabilities =
      typeof params.capabilities === 'object' && params.capabilities !== null
        ? (params.capabilities as Record<string, unknown>)
        : {};

    const rawExtensions = getNestedValue(this.capabilities, 'extensions');
    this.extensions =
      typeof rawExtensions === 'object' && rawExtensions !== null
        ? (rawExtensions as Record<string, unknown>)
        : {};

    // -- UI extension -----------------------------------------------------
    this.uiExtensionAvailable = UI_EXTENSION_KEY in this.extensions;

    if (this.uiExtensionAvailable) {
      const uiExt = this.extensions[UI_EXTENSION_KEY] as Record<string, unknown> | undefined;
      const rawMimeTypes = uiExt?.mimeTypes;
      this.supportedMimeTypes = Array.isArray(rawMimeTypes)
        ? rawMimeTypes.filter((m): m is string => typeof m === 'string')
        : [];
    } else {
      this.supportedMimeTypes = [];
    }

    // -- Cowork detection -------------------------------------------------
    // Cowork is active when the protocol version is at least 2025-06-18 OR
    // when the client name contains recognisable Cowork markers.
    const versionIsCowork = compareVersionStrings(this.protocolVersion, PROTOCOL_COWORK) >= 0;
    const nameHintsCowork =
      this.clientName.toLowerCase().includes('cowork') ||
      this.clientName.toLowerCase().includes('claude-desktop-next');
    this.coworkEnabled = versionIsCowork || nameHintsCowork;

    // -- Compatibility notes ----------------------------------------------
    this.notes = this.buildCompatibilityNotes();

    return {
      version: this.protocolVersion,
      isCowork: this.coworkEnabled,
      hasUI: this.uiExtensionAvailable,
      clientName: this.clientName,
      clientVersion: this.clientVersion,
      extensions: { ...this.extensions },
      compatibilityNotes: [...this.notes],
    };
  }

  // ── Capability queries ────────────────────────────────────────────────────

  /** Returns `true` when the connected client advertised the UI extension. */
  hasUIExtension(): boolean {
    return this.uiExtensionAvailable;
  }

  /**
   * Check whether an arbitrary capability (by dotted path) was advertised by
   * the client.  For example:
   *
   *     handler.hasCapability('extensions.io.modelcontextprotocol/ui')
   *     handler.hasCapability('roots')
   */
  hasCapability(name: string): boolean {
    return getNestedValue(this.capabilities, name) !== undefined;
  }

  /** Returns basic identity information about the connected client. */
  getClientInfo(): ClientInfo {
    return {
      name: this.clientName,
      version: this.clientVersion,
      protocolVersion: this.protocolVersion,
    };
  }

  /**
   * Returns the MIME types that the connected client declared it can render
   * via the UI extension.  Empty when the UI extension is absent.
   */
  getSupportedMimeTypes(): string[] {
    return [...this.supportedMimeTypes];
  }

  // ── Server capability advertisement ───────────────────────────────────────

  /**
   * Build the `capabilities` object that the bridge should return in its
   * `initialize` response.  The shape adapts to the detected protocol
   * version so that newer features are only advertised to clients that
   * understand them.
   */
  getServerCapabilities(bridgeName: string): ServerCapabilities {
    const caps: ServerCapabilities = {
      tools: {} as Record<string, never>,
    };

    // Logging is a first-class concept starting with the Cowork protocol.
    if (compareVersionStrings(this.protocolVersion, PROTOCOL_COWORK) >= 0) {
      caps.logging = {} as Record<string, never>;
    }

    // Bridge-specific experimental capabilities, keyed by bridge name so
    // multiple bridges can coexist without collisions.
    caps.experimental = {
      [`bridge/${bridgeName}`]: {
        version: '0.2.0',
        protocolDetected: this.protocolVersion,
        coworkEnabled: this.coworkEnabled,
      },
    };

    return caps;
  }

  // ── Notification helpers (JSON-RPC 2.0) ───────────────────────────────────

  /**
   * Create a progress notification message conforming to the MCP spec.
   *
   * ```jsonc
   * {
   *   "jsonrpc": "2.0",
   *   "method": "notifications/progress",
   *   "params": { "progressToken": "...", "progress": 3, "total": 10, "message": "..." }
   * }
   * ```
   */
  createProgressNotification(
    token: string,
    progress: number,
    total: number,
    message?: string,
  ): { jsonrpc: '2.0'; method: string; params: Record<string, unknown> } {
    const params: Record<string, unknown> = {
      progressToken: token,
      progress,
      total,
    };
    if (message !== undefined) {
      params.message = message;
    }
    return {
      jsonrpc: '2.0',
      method: 'notifications/progress',
      params,
    };
  }

  /**
   * Create a log notification message conforming to the MCP spec.
   *
   * ```jsonc
   * {
   *   "jsonrpc": "2.0",
   *   "method": "notifications/message",
   *   "params": { "level": "info", "logger": "bridge-name", "data": ..., "message": "..." }
   * }
   * ```
   */
  createLogNotification(
    level: 'debug' | 'info' | 'warning' | 'error',
    message: string,
    data?: unknown,
  ): { jsonrpc: '2.0'; method: string; params: Record<string, unknown> } {
    const params: Record<string, unknown> = {
      level,
      logger: `mcp-bridge/${this.clientName}`,
      message,
    };
    if (data !== undefined) {
      params.data = typeof data === 'string' ? data : JSON.stringify(data);
    }
    return {
      jsonrpc: '2.0',
      method: 'notifications/message',
      params,
    };
  }

  // ── Response formatting ────────────────────────────────────────────────────

  /**
   * Format a tool call response.
   *
   * When `options.useHTML` is `true` **and** the client supports the UI
   * extension, the content is wrapped in an HTML content block with the
   * appropriate MIME type.  Otherwise plain-text blocks are returned.
   *
   * Accepts either a single string or a pre-built array of content blocks.
   */
  formatToolResponse(
    content: string | ContentBlock[],
    options: ResponseOptions = {},
  ): ToolResponse {
    const { useHTML = false, mimeType, isError = false } = options;

    // Pre-built content block array: pass through with minimal wrapping.
    if (Array.isArray(content)) {
      return {
        content: content.map((block) => ({ ...block })),
        ...(isError ? { isError: true } : {}),
      };
    }

    // Determine whether we should emit HTML.
    const shouldEmitHTML =
      useHTML && this.uiExtensionAvailable && this.supportedMimeTypes.includes(HTML_MIME_TYPE);

    if (shouldEmitHTML) {
      const resolvedMimeType = mimeType ?? HTML_MIME_TYPE;
      const htmlContent = this.wrapInHTMLDocument(content);
      return {
        content: [
          {
            type: 'text',
            text: htmlContent,
            mimeType: resolvedMimeType,
          },
        ],
        ...(isError ? { isError: true } : {}),
      };
    }

    // Default: plain text.
    return {
      content: [{ type: 'text', text: content }],
      ...(isError ? { isError: true } : {}),
    };
  }

  // ── Version compatibility ─────────────────────────────────────────────────

  /** Returns `true` when the Cowork protocol (or newer) is in use. */
  isCoworkEnabled(): boolean {
    return this.coworkEnabled;
  }

  /** Returns the raw protocol version string received from the client. */
  getProtocolVersion(): string {
    return this.protocolVersion;
  }

  /** Returns human-readable notes about the detected compatibility level. */
  getCompatibilityNotes(): string[] {
    return [...this.notes];
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private buildCompatibilityNotes(): string[] {
    const notes: string[] = [];

    // Protocol-level notes.
    if (compareVersionStrings(this.protocolVersion, PROTOCOL_COWORK) >= 0) {
      notes.push('Cowork protocol - full UI support available');
    } else if (this.protocolVersion === PROTOCOL_CLASSIC) {
      notes.push('Classic protocol - UI extensions not available');
    } else {
      notes.push(`Unknown protocol version ${this.protocolVersion} - treating as classic`);
    }

    // UI extension.
    if (this.uiExtensionAvailable) {
      notes.push(`UI extension active - supported MIME types: ${this.supportedMimeTypes.join(', ') || '(none declared)'}`);
    }

    // General operational notes that apply regardless of version.
    notes.push('CWD may be system directory - use import.meta.url for paths');
    notes.push('MCP Registry available for skill discovery');

    return notes;
  }

  /**
   * Wrap raw text/HTML content in a minimal HTML5 document so that clients
   * rendering `text/html;profile=mcp-app` receive a well-formed page.
   * If the content already looks like a complete document (starts with
   * `<!DOCTYPE` or `<html`), it is returned unchanged.
   */
  private wrapInHTMLDocument(content: string): string {
    const trimmed = content.trimStart();
    if (trimmed.startsWith('<!DOCTYPE') || trimmed.startsWith('<!doctype') || trimmed.toLowerCase().startsWith('<html')) {
      return content;
    }

    return [
      '<!DOCTYPE html>',
      '<html lang="en">',
      '<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>',
      '<body>',
      content,
      '</body>',
      '</html>',
    ].join('\n');
  }
}
