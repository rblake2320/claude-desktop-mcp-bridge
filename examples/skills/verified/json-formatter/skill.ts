/**
 * JSON Formatter Skill - VERIFIED
 *
 * A clean, secure skill that demonstrates proper JSON formatting capabilities
 * without any dangerous operations. Perfect golden-path example for VERIFIED trust level.
 */

export const name = "json-formatter";
export const description = "Format, validate, and beautify JSON data with syntax highlighting and error detection";
export const category = "standard";

export const triggers = [
  "format json",
  "json format",
  "beautify json",
  "validate json",
  "minify json",
  "json pretty",
  "fix json"
];

export const pairsWith = [
  "code-review-agent",
  "clean-code"
];

export const capabilities = [
  "json-format",
  "json-validate",
  "json-minify",
  "json-beautify"
];

/**
 * Main skill execution function
 */
export async function execute(args: string): Promise<string> {
  const input = args.trim();

  if (!input) {
    return showHelp();
  }

  // Parse command and options
  const parts = input.split(' ');
  const command = parts[0].toLowerCase();
  const jsonInput = parts.slice(1).join(' ');

  try {
    switch (command) {
      case 'format':
      case 'beautify':
      case 'pretty':
        return formatJson(jsonInput);

      case 'minify':
      case 'compact':
        return minifyJson(jsonInput);

      case 'validate':
      case 'check':
        return validateJson(jsonInput);

      case 'help':
        return showHelp();

      default:
        // If no command, assume format
        return formatJson(input);
    }
  } catch (error) {
    return `❌ Error: ${error instanceof Error ? error.message : String(error)}`;
  }
}

/**
 * Format and beautify JSON with proper indentation
 */
function formatJson(input: string): string {
  if (!input.trim()) {
    return "❌ No JSON input provided";
  }

  try {
    const parsed = JSON.parse(input);
    const formatted = JSON.stringify(parsed, null, 2);

    return `✅ JSON formatted successfully:

\`\`\`json
${formatted}
\`\`\`

📊 **Stats**: ${countJsonElements(parsed)} elements, ${formatted.length} characters`;

  } catch (error) {
    if (error instanceof SyntaxError) {
      return formatSyntaxError(error, input);
    }
    throw error;
  }
}

/**
 * Minify JSON by removing whitespace
 */
function minifyJson(input: string): string {
  if (!input.trim()) {
    return "❌ No JSON input provided";
  }

  try {
    const parsed = JSON.parse(input);
    const minified = JSON.stringify(parsed);
    const originalSize = input.length;
    const newSize = minified.length;
    const savings = Math.round(((originalSize - newSize) / originalSize) * 100);

    return `✅ JSON minified successfully:

\`\`\`json
${minified}
\`\`\`

📊 **Compression**: ${originalSize} → ${newSize} chars (${savings}% reduction)`;

  } catch (error) {
    if (error instanceof SyntaxError) {
      return formatSyntaxError(error, input);
    }
    throw error;
  }
}

/**
 * Validate JSON syntax and structure
 */
function validateJson(input: string): string {
  if (!input.trim()) {
    return "❌ No JSON input provided";
  }

  try {
    const parsed = JSON.parse(input);
    const stats = analyzeJson(parsed);

    return `✅ **Valid JSON!**

📋 **Structure Analysis**:
- Type: ${stats.type}
- Elements: ${stats.elements}
- Depth: ${stats.depth}
- Size: ${input.length} characters

${stats.warnings.length > 0 ? '⚠️ **Warnings**:\n' + stats.warnings.map(w => `- ${w}`).join('\n') : ''}`;

  } catch (error) {
    if (error instanceof SyntaxError) {
      return formatSyntaxError(error, input);
    }
    throw error;
  }
}

/**
 * Format syntax error with helpful context
 */
function formatSyntaxError(error: SyntaxError, input: string): string {
  const message = error.message;
  const lines = input.split('\n');

  // Try to extract position from error
  const posMatch = message.match(/position (\d+)/);
  let context = '';

  if (posMatch) {
    const pos = parseInt(posMatch[1]);
    const beforePos = Math.max(0, pos - 20);
    const afterPos = Math.min(input.length, pos + 20);
    const snippet = input.slice(beforePos, afterPos);
    const pointer = ' '.repeat(Math.min(20, pos - beforePos)) + '^';

    context = `

**Error Location**:
\`\`\`
${snippet}
${pointer}
\`\`\``;
  }

  return `❌ **Invalid JSON**: ${message}${context}

💡 **Common Issues**:
- Missing or extra commas
- Unquoted property names
- Single quotes instead of double quotes
- Trailing commas (not allowed in JSON)`;
}

/**
 * Analyze JSON structure for insights
 */
function analyzeJson(data: any): {
  type: string;
  elements: number;
  depth: number;
  warnings: string[];
} {
  const warnings: string[] = [];

  const type = Array.isArray(data) ? 'Array' :
               data === null ? 'null' :
               typeof data === 'object' ? 'Object' :
               typeof data;

  const elements = countJsonElements(data);
  const depth = calculateDepth(data);

  // Add warnings for potential issues
  if (depth > 10) {
    warnings.push('Very deep nesting detected (>10 levels)');
  }

  if (elements > 1000) {
    warnings.push('Large JSON structure (>1000 elements)');
  }

  return { type, elements, depth, warnings };
}

/**
 * Count total elements in JSON structure
 */
function countJsonElements(data: any): number {
  if (data === null || typeof data !== 'object') {
    return 1;
  }

  if (Array.isArray(data)) {
    return 1 + data.reduce((sum, item) => sum + countJsonElements(item), 0);
  }

  return 1 + Object.values(data).reduce((sum, value) => sum + countJsonElements(value), 0);
}

/**
 * Calculate maximum depth of JSON structure
 */
function calculateDepth(data: any, current = 0): number {
  if (data === null || typeof data !== 'object') {
    return current;
  }

  const values = Array.isArray(data) ? data : Object.values(data);

  if (values.length === 0) {
    return current + 1;
  }

  return Math.max(...values.map(value => calculateDepth(value, current + 1)));
}

/**
 * Show help and usage examples
 */
function showHelp(): string {
  return `# 🔧 JSON Formatter Skill

**Usage**: \`json-formatter <command> <json_data>\`

## Commands

**Format/Beautify**:
- \`json-formatter format {"name":"John","age":30}\`
- \`json-formatter pretty [1,2,3]\`

**Minify**:
- \`json-formatter minify { "name": "John", "age": 30 }\`

**Validate**:
- \`json-formatter validate {"test": "data"}\`

**Direct Formatting** (no command):
- \`json-formatter {"name":"John","age":30}\`

## Examples

\`\`\`
json-formatter format {"users":[{"name":"Alice"},{"name":"Bob"}]}
json-formatter validate {"key": "value"
json-formatter minify { "a": 1, "b": 2 }
\`\`\`

*This is a VERIFIED skill - secure, tested, and trusted.*`;
}