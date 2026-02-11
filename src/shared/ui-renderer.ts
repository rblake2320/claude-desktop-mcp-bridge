/**
 * ui-renderer.ts
 *
 * Rich HTML rendering for MCP servers when the client advertises
 * the `io.modelcontextprotocol/ui` extension.
 *
 * Claude Desktop with Cowork sends:
 *   "capabilities": {
 *     "extensions": {
 *       "io.modelcontextprotocol/ui": {
 *         "mimeTypes": ["text/html;profile=mcp-app"]
 *       }
 *     }
 *   }
 *
 * When UI support is detected, render methods return styled HTML.
 * Otherwise they return equivalent plain-text representations.
 */

// ── Types ────────────────────────────────────────────────────────────────────

/** Content block returned by every render method. */
export interface ContentBlock {
  type: string;
  text: string;
}

/** Skill descriptor accepted by card/list renderers. */
export interface SkillInfo {
  name: string;
  description: string;
  category: string;
  triggers?: string[];
  score?: number;
}

/** A single step in an orchestration pipeline. */
export interface OrchestrationStep {
  name: string;
  status: 'success' | 'error' | 'pending';
  output?: string;
}

/** Code block descriptor for the guidance renderer. */
export interface CodeBlockDescriptor {
  language: string;
  code: string;
}

/** Shape of client capabilities that may include UI extension. */
export interface ClientCapabilities {
  extensions?: {
    'io.modelcontextprotocol/ui'?: {
      mimeTypes?: string[];
    };
  };
  [key: string]: unknown;
}

// ── Design Tokens ────────────────────────────────────────────────────────────

const COLORS = {
  bg:        '#1a1a2e',
  bgCard:    '#16213e',
  bgCode:    '#0f0f23',
  bgInset:   '#1e2a45',
  text:      '#e0e0e0',
  textMuted: '#9ca3af',
  border:    '#2a2a4a',
  blue:      '#4cc9f0',
  green:     '#4ade80',
  red:       '#f87171',
  yellow:    '#fbbf24',
  orange:    '#fb923c',
} as const;

const FONTS = {
  sans:  "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
  mono:  "'SF Mono', Menlo, Monaco, 'Cascadia Code', monospace",
} as const;

// ── Shared CSS fragments ─────────────────────────────────────────────────────

function baseStyles(): string {
  return `
    font-family: ${FONTS.sans};
    color: ${COLORS.text};
    background: ${COLORS.bg};
    line-height: 1.5;
    margin: 0;
    padding: 16px;
    box-sizing: border-box;
  `;
}

function cardStyles(): string {
  return `
    background: ${COLORS.bgCard};
    border: 1px solid ${COLORS.border};
    border-radius: 8px;
    padding: 16px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.25);
    margin-bottom: 12px;
  `;
}

// ── HTML Helpers ─────────────────────────────────────────────────────────────

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function wrapHtml(body: string): string {
  return `<div style="${baseStyles()}">${body}</div>`;
}

function badge(label: string, color: string): string {
  return `<span style="
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 600;
    background: ${color}22;
    color: ${color};
    border: 1px solid ${color}44;
    margin-right: 6px;
    margin-bottom: 4px;
  ">${escapeHtml(label)}</span>`;
}

function statusIcon(status: 'success' | 'error' | 'pending'): string {
  switch (status) {
    case 'success': return `<span style="color:${COLORS.green};">&#10003;</span>`;
    case 'error':   return `<span style="color:${COLORS.red};">&#10007;</span>`;
    case 'pending': return `<span style="color:${COLORS.yellow};">&#9679;</span>`;
  }
}

function statusLabel(status: 'success' | 'error' | 'pending'): string {
  switch (status) {
    case 'success': return '[OK]';
    case 'error':   return '[FAIL]';
    case 'pending': return '[...]';
  }
}

function categoryColor(category: string): string {
  const map: Record<string, string> = {
    standard:     COLORS.blue,
    utility:      COLORS.green,
    development:  COLORS.yellow,
    security:     COLORS.red,
    experimental: COLORS.orange,
  };
  return map[category.toLowerCase()] ?? COLORS.blue;
}

function codeBlock(language: string, code: string): string {
  return `<div style="margin: 8px 0;">
    <div style="
      font-size: 11px;
      color: ${COLORS.textMuted};
      margin-bottom: 2px;
      font-family: ${FONTS.mono};
    ">${escapeHtml(language)}</div>
    <pre style="
      background: ${COLORS.bgCode};
      border: 1px solid ${COLORS.border};
      border-radius: 6px;
      padding: 12px;
      margin: 0;
      overflow-x: auto;
      font-family: ${FONTS.mono};
      font-size: 13px;
      line-height: 1.45;
      color: ${COLORS.text};
    "><code>${escapeHtml(code)}</code></pre>
  </div>`;
}

function heading(text: string, level: 1 | 2 | 3 = 1): string {
  const sizes: Record<number, string> = { 1: '20px', 2: '16px', 3: '14px' };
  return `<div style="
    font-size: ${sizes[level]};
    font-weight: 700;
    color: ${COLORS.text};
    margin-bottom: 12px;
    padding-bottom: 8px;
    border-bottom: 1px solid ${COLORS.border};
  ">${escapeHtml(text)}</div>`;
}

// ── UIRenderer ───────────────────────────────────────────────────────────────

/**
 * Detects client UI capabilities and renders rich HTML or plain-text content
 * blocks for MCP tool responses.
 */
export class UIRenderer {

  private static uiEnabled = false;

  /**
   * Inspect the client capabilities object sent during MCP initialisation
   * and return `true` when the client supports the UI extension with HTML.
   */
  static detectUISupport(clientCapabilities: ClientCapabilities | unknown): boolean {
    if (!clientCapabilities || typeof clientCapabilities !== 'object') {
      return false;
    }

    const caps = clientCapabilities as ClientCapabilities;
    const uiExt = caps.extensions?.['io.modelcontextprotocol/ui'];

    if (!uiExt || typeof uiExt !== 'object') {
      return false;
    }

    const mimeTypes = uiExt.mimeTypes;

    if (!Array.isArray(mimeTypes)) {
      return false;
    }

    return mimeTypes.some(
      (m) => typeof m === 'string' && m.includes('text/html'),
    );
  }

  /** Globally enable or disable HTML rendering. */
  static setUIEnabled(enabled: boolean): void {
    UIRenderer.uiEnabled = enabled;
  }

  /** Check whether HTML rendering is currently active. */
  static isUIEnabled(): boolean {
    return UIRenderer.uiEnabled;
  }

  // ── Skill Card ───────────────────────────────────────────────────────────

  /**
   * Render a single skill as a styled card (HTML) or a concise text block.
   */
  static renderSkillCard(skill: SkillInfo): ContentBlock {
    if (!UIRenderer.uiEnabled) {
      return UIRenderer.skillCardPlain(skill);
    }

    const color = categoryColor(skill.category);
    const triggerBadges = (skill.triggers ?? [])
      .map((t) => badge(t, COLORS.blue))
      .join('');

    const scoreSection = skill.score != null
      ? `<div style="
          margin-top: 10px;
          font-size: 13px;
          color: ${COLORS.textMuted};
        ">Match score: <strong style="color:${COLORS.green};">${skill.score.toFixed(2)}</strong></div>`
      : '';

    const html = wrapHtml(`
      <div style="${cardStyles()}">
        <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:8px;">
          <span style="font-size:16px; font-weight:700; color:${COLORS.text};">${escapeHtml(skill.name)}</span>
          ${badge(skill.category, color)}
        </div>
        <div style="color:${COLORS.textMuted}; font-size:14px; margin-bottom:10px;">
          ${escapeHtml(skill.description)}
        </div>
        ${triggerBadges ? `<div style="margin-top:6px;">${triggerBadges}</div>` : ''}
        ${scoreSection}
      </div>
    `);

    return { type: 'text', text: html };
  }

  private static skillCardPlain(skill: SkillInfo): ContentBlock {
    const lines: string[] = [];
    lines.push(`[${skill.category.toUpperCase()}] ${skill.name}`);
    lines.push(skill.description);
    if (skill.triggers && skill.triggers.length > 0) {
      lines.push(`Triggers: ${skill.triggers.join(', ')}`);
    }
    if (skill.score != null) {
      lines.push(`Match score: ${skill.score.toFixed(2)}`);
    }
    return { type: 'text', text: lines.join('\n') };
  }

  // ── Skill List ───────────────────────────────────────────────────────────

  /**
   * Render a titled list of skills.
   */
  static renderSkillList(
    skills: SkillInfo[],
    title: string,
  ): ContentBlock {
    if (!UIRenderer.uiEnabled) {
      return UIRenderer.skillListPlain(skills, title);
    }

    const rows = skills.map((s) => {
      const color = categoryColor(s.category);
      const triggers = (s.triggers ?? [])
        .slice(0, 3)
        .map((t) => badge(t, COLORS.blue))
        .join('');

      return `<tr>
        <td style="padding:8px 12px; border-bottom:1px solid ${COLORS.border};">
          <strong style="color:${COLORS.text};">${escapeHtml(s.name)}</strong>
        </td>
        <td style="padding:8px 12px; border-bottom:1px solid ${COLORS.border}; color:${COLORS.textMuted}; font-size:13px;">
          ${escapeHtml(s.description)}
        </td>
        <td style="padding:8px 12px; border-bottom:1px solid ${COLORS.border};">
          ${badge(s.category, color)}
        </td>
        <td style="padding:8px 12px; border-bottom:1px solid ${COLORS.border};">
          ${triggers}
        </td>
      </tr>`;
    }).join('');

    const html = wrapHtml(`
      ${heading(title)}
      <div style="overflow-x:auto;">
        <table style="width:100%; border-collapse:collapse; font-size:14px;">
          <thead>
            <tr style="text-align:left;">
              <th style="padding:8px 12px; border-bottom:2px solid ${COLORS.border}; color:${COLORS.textMuted}; font-size:12px; text-transform:uppercase; letter-spacing:0.5px;">Name</th>
              <th style="padding:8px 12px; border-bottom:2px solid ${COLORS.border}; color:${COLORS.textMuted}; font-size:12px; text-transform:uppercase; letter-spacing:0.5px;">Description</th>
              <th style="padding:8px 12px; border-bottom:2px solid ${COLORS.border}; color:${COLORS.textMuted}; font-size:12px; text-transform:uppercase; letter-spacing:0.5px;">Category</th>
              <th style="padding:8px 12px; border-bottom:2px solid ${COLORS.border}; color:${COLORS.textMuted}; font-size:12px; text-transform:uppercase; letter-spacing:0.5px;">Triggers</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      <div style="margin-top:12px; font-size:12px; color:${COLORS.textMuted};">
        ${skills.length} skill${skills.length !== 1 ? 's' : ''} listed
      </div>
    `);

    return { type: 'text', text: html };
  }

  private static skillListPlain(skills: SkillInfo[], title: string): ContentBlock {
    const header = `--- ${title} (${skills.length}) ---`;
    const rows = skills.map((s) => {
      const triggers = (s.triggers ?? []).join(', ');
      const triggerPart = triggers ? ` | Triggers: ${triggers}` : '';
      return `  [${s.category}] ${s.name} - ${s.description}${triggerPart}`;
    });
    return { type: 'text', text: [header, ...rows].join('\n') };
  }

  // ── Guidance ─────────────────────────────────────────────────────────────

  /**
   * Render skill guidance or documentation with optional code blocks.
   */
  static renderGuidance(
    title: string,
    content: string,
    codeBlocks?: CodeBlockDescriptor[],
  ): ContentBlock {
    if (!UIRenderer.uiEnabled) {
      return UIRenderer.guidancePlain(title, content, codeBlocks);
    }

    const codeHtml = (codeBlocks ?? [])
      .map((cb) => codeBlock(cb.language, cb.code))
      .join('');

    const paragraphs = content
      .split(/\n{2,}/)
      .map((p) => `<p style="margin:0 0 10px 0; color:${COLORS.text}; font-size:14px;">${escapeHtml(p.trim())}</p>`)
      .join('');

    const html = wrapHtml(`
      <div style="${cardStyles()}">
        ${heading(title, 2)}
        ${paragraphs}
        ${codeHtml}
      </div>
    `);

    return { type: 'text', text: html };
  }

  private static guidancePlain(
    title: string,
    content: string,
    codeBlocks?: CodeBlockDescriptor[],
  ): ContentBlock {
    const lines: string[] = [];
    lines.push(`=== ${title} ===`);
    lines.push('');
    lines.push(content);
    if (codeBlocks && codeBlocks.length > 0) {
      for (const cb of codeBlocks) {
        lines.push('');
        lines.push(`--- ${cb.language} ---`);
        lines.push(cb.code);
        lines.push('---');
      }
    }
    return { type: 'text', text: lines.join('\n') };
  }

  // ── Error ────────────────────────────────────────────────────────────────

  /**
   * Render an error message with optional detail text.
   */
  static renderError(message: string, details?: string): ContentBlock {
    if (!UIRenderer.uiEnabled) {
      return UIRenderer.errorPlain(message, details);
    }

    const detailHtml = details
      ? `<pre style="
          margin-top:10px;
          padding:10px;
          background:${COLORS.bgCode};
          border-radius:6px;
          font-family:${FONTS.mono};
          font-size:12px;
          color:${COLORS.textMuted};
          white-space:pre-wrap;
          word-break:break-word;
          overflow-x:auto;
        ">${escapeHtml(details)}</pre>`
      : '';

    const html = wrapHtml(`
      <div style="
        ${cardStyles()}
        border-left: 4px solid ${COLORS.red};
      ">
        <div style="display:flex; align-items:center; gap:8px; margin-bottom:6px;">
          <span style="color:${COLORS.red}; font-size:18px;">&#9888;</span>
          <span style="font-size:15px; font-weight:700; color:${COLORS.red};">Error</span>
        </div>
        <div style="color:${COLORS.text}; font-size:14px;">${escapeHtml(message)}</div>
        ${detailHtml}
      </div>
    `);

    return { type: 'text', text: html };
  }

  private static errorPlain(message: string, details?: string): ContentBlock {
    const lines = [`ERROR: ${message}`];
    if (details) {
      lines.push('');
      lines.push(details);
    }
    return { type: 'text', text: lines.join('\n') };
  }

  // ── Stats Dashboard ──────────────────────────────────────────────────────

  /**
   * Render a set of key/value statistics as a mini dashboard.
   */
  static renderStats(stats: Record<string, string | number>): ContentBlock {
    if (!UIRenderer.uiEnabled) {
      return UIRenderer.statsPlain(stats);
    }

    const entries = Object.entries(stats);
    const cells = entries.map(([key, value]) => {
      const isNumber = typeof value === 'number';
      return `<div style="
        flex: 1 1 140px;
        background: ${COLORS.bgInset};
        border: 1px solid ${COLORS.border};
        border-radius: 8px;
        padding: 14px 16px;
        min-width: 140px;
      ">
        <div style="
          font-size: 11px;
          text-transform: uppercase;
          letter-spacing: 0.5px;
          color: ${COLORS.textMuted};
          margin-bottom: 6px;
        ">${escapeHtml(key)}</div>
        <div style="
          font-size: ${isNumber ? '22px' : '15px'};
          font-weight: 700;
          color: ${isNumber ? COLORS.blue : COLORS.text};
          font-family: ${isNumber ? FONTS.mono : FONTS.sans};
        ">${escapeHtml(String(value))}</div>
      </div>`;
    }).join('');

    const html = wrapHtml(`
      ${heading('Statistics', 2)}
      <div style="
        display: flex;
        flex-wrap: wrap;
        gap: 12px;
      ">${cells}</div>
    `);

    return { type: 'text', text: html };
  }

  private static statsPlain(stats: Record<string, string | number>): ContentBlock {
    const maxKeyLen = Math.max(...Object.keys(stats).map((k) => k.length));
    const lines = Object.entries(stats).map(
      ([key, value]) => `  ${key.padEnd(maxKeyLen)}  ${value}`,
    );
    return { type: 'text', text: ['--- Statistics ---', ...lines].join('\n') };
  }

  // ── Approval Dialog ──────────────────────────────────────────────────────

  /**
   * Render a trust-approval dialog for a skill that requires user review.
   */
  static renderApprovalDialog(
    skillName: string,
    trustLevel: string,
    issues: string[],
  ): ContentBlock {
    if (!UIRenderer.uiEnabled) {
      return UIRenderer.approvalDialogPlain(skillName, trustLevel, issues);
    }

    const trustColor = trustLevel === 'untrusted'
      ? COLORS.red
      : trustLevel === 'verified'
        ? COLORS.green
        : COLORS.yellow;

    const issueItems = issues
      .map((issue) => `<li style="
        margin-bottom:6px;
        color:${COLORS.text};
        font-size:13px;
      ">${escapeHtml(issue)}</li>`)
      .join('');

    const html = wrapHtml(`
      <div style="
        ${cardStyles()}
        border-left: 4px solid ${COLORS.yellow};
      ">
        <div style="display:flex; align-items:center; gap:8px; margin-bottom:10px;">
          <span style="color:${COLORS.yellow}; font-size:20px;">&#9888;</span>
          <span style="font-size:16px; font-weight:700; color:${COLORS.text};">Skill Approval Required</span>
        </div>

        <div style="
          display:flex;
          align-items:center;
          gap:10px;
          margin-bottom:14px;
          padding:10px 14px;
          background:${COLORS.bgInset};
          border-radius:6px;
        ">
          <div>
            <div style="font-size:14px; font-weight:600; color:${COLORS.text};">${escapeHtml(skillName)}</div>
            <div style="margin-top:4px;">
              ${badge(trustLevel, trustColor)}
            </div>
          </div>
        </div>

        ${issues.length > 0 ? `
          <div style="margin-bottom:10px;">
            <div style="font-size:13px; font-weight:600; color:${COLORS.textMuted}; margin-bottom:6px;">Issues to Review:</div>
            <ul style="margin:0; padding-left:20px;">${issueItems}</ul>
          </div>
        ` : ''}

        <div style="
          margin-top:14px;
          padding-top:12px;
          border-top:1px solid ${COLORS.border};
          font-size:12px;
          color:${COLORS.textMuted};
        ">
          Use <code style="
            font-family:${FONTS.mono};
            background:${COLORS.bgCode};
            padding:2px 6px;
            border-radius:3px;
            font-size:12px;
          ">approve_skill</code> or <code style="
            font-family:${FONTS.mono};
            background:${COLORS.bgCode};
            padding:2px 6px;
            border-radius:3px;
            font-size:12px;
          ">reject_skill</code> to proceed.
        </div>
      </div>
    `);

    return { type: 'text', text: html };
  }

  private static approvalDialogPlain(
    skillName: string,
    trustLevel: string,
    issues: string[],
  ): ContentBlock {
    const lines: string[] = [];
    lines.push('*** SKILL APPROVAL REQUIRED ***');
    lines.push(`Skill:       ${skillName}`);
    lines.push(`Trust Level: ${trustLevel}`);
    if (issues.length > 0) {
      lines.push('');
      lines.push('Issues:');
      for (const issue of issues) {
        lines.push(`  - ${issue}`);
      }
    }
    lines.push('');
    lines.push('Use `approve_skill` or `reject_skill` to proceed.');
    return { type: 'text', text: lines.join('\n') };
  }

  // ── Orchestration Result ─────────────────────────────────────────────────

  /**
   * Render the result of a multi-step orchestration pipeline.
   */
  static renderOrchestrationResult(steps: OrchestrationStep[]): ContentBlock {
    if (!UIRenderer.uiEnabled) {
      return UIRenderer.orchestrationPlain(steps);
    }

    const statusColors: Record<string, string> = {
      success: COLORS.green,
      error:   COLORS.red,
      pending: COLORS.yellow,
    };

    const stepRows = steps.map((step, idx) => {
      const color = statusColors[step.status] ?? COLORS.textMuted;
      const outputHtml = step.output
        ? `<div style="
            margin-top:6px;
            padding:8px 10px;
            background:${COLORS.bgCode};
            border-radius:4px;
            font-family:${FONTS.mono};
            font-size:12px;
            color:${COLORS.textMuted};
            white-space:pre-wrap;
            word-break:break-word;
          ">${escapeHtml(step.output)}</div>`
        : '';

      return `<div style="
        display:flex;
        gap:12px;
        padding:10px 0;
        ${idx < steps.length - 1 ? `border-bottom:1px solid ${COLORS.border};` : ''}
      ">
        <div style="
          flex-shrink:0;
          width:28px;
          height:28px;
          border-radius:50%;
          background:${color}18;
          border:2px solid ${color};
          display:flex;
          align-items:center;
          justify-content:center;
          font-size:14px;
        ">${statusIcon(step.status)}</div>
        <div style="flex:1; min-width:0;">
          <div style="
            font-size:14px;
            font-weight:600;
            color:${COLORS.text};
          ">${escapeHtml(step.name)}</div>
          <div style="
            font-size:12px;
            color:${color};
            margin-top:2px;
          ">${step.status.charAt(0).toUpperCase() + step.status.slice(1)}</div>
          ${outputHtml}
        </div>
      </div>`;
    }).join('');

    const successCount = steps.filter((s) => s.status === 'success').length;
    const errorCount   = steps.filter((s) => s.status === 'error').length;
    const pendingCount = steps.filter((s) => s.status === 'pending').length;

    const summaryParts: string[] = [];
    if (successCount > 0) summaryParts.push(`<span style="color:${COLORS.green};">${successCount} passed</span>`);
    if (errorCount > 0)   summaryParts.push(`<span style="color:${COLORS.red};">${errorCount} failed</span>`);
    if (pendingCount > 0) summaryParts.push(`<span style="color:${COLORS.yellow};">${pendingCount} pending</span>`);

    const html = wrapHtml(`
      <div style="${cardStyles()}">
        ${heading('Orchestration Result', 2)}
        ${stepRows}
        <div style="
          margin-top:14px;
          padding-top:10px;
          border-top:1px solid ${COLORS.border};
          font-size:13px;
          color:${COLORS.textMuted};
        ">
          ${steps.length} step${steps.length !== 1 ? 's' : ''}: ${summaryParts.join(' &middot; ')}
        </div>
      </div>
    `);

    return { type: 'text', text: html };
  }

  private static orchestrationPlain(steps: OrchestrationStep[]): ContentBlock {
    const lines: string[] = ['--- Orchestration Result ---', ''];

    for (const step of steps) {
      const label = statusLabel(step.status);
      lines.push(`${label} ${step.name}`);
      if (step.output) {
        const indented = step.output
          .split('\n')
          .map((l) => `       ${l}`)
          .join('\n');
        lines.push(indented);
      }
    }

    const successCount = steps.filter((s) => s.status === 'success').length;
    const errorCount   = steps.filter((s) => s.status === 'error').length;
    const pendingCount = steps.filter((s) => s.status === 'pending').length;

    lines.push('');
    const parts: string[] = [];
    if (successCount > 0) parts.push(`${successCount} passed`);
    if (errorCount > 0)   parts.push(`${errorCount} failed`);
    if (pendingCount > 0) parts.push(`${pendingCount} pending`);
    lines.push(`${steps.length} steps: ${parts.join(', ')}`);

    return { type: 'text', text: lines.join('\n') };
  }
}
