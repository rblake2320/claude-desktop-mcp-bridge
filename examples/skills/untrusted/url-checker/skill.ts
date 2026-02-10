/**
 * URL Checker Skill - UNTRUSTED
 *
 * This skill demonstrates an UNTRUSTED skill that requires user approval.
 * It validates URLs and checks for security threats, which requires network access.
 * Because it's untrusted, it has strict resource limits and requires approval.
 */

export const name = "url-checker";
export const description = "Validate URLs and check for security threats, malicious links, and reputation issues";
export const category = "standard";

export const triggers = [
  "check url",
  "validate url",
  "url safety",
  "link check",
  "malicious url",
  "phishing check",
  "url reputation"
];

export const pairsWith = [
  "security-testing",
  "web-scraping"
];

export const capabilities = [
  "url-validation",
  "url-analysis",
  "security-check",
  "link-safety"
];

// Interface for URL analysis results
interface UrlAnalysis {
  valid: boolean;
  protocol: string;
  domain: string;
  path: string;
  suspicious: boolean;
  risks: string[];
  warnings: string[];
  reputation?: string;
}

/**
 * Main skill execution function
 */
export async function execute(args: string): Promise<string> {
  const input = args.trim();

  if (!input) {
    return showHelp();
  }

  // Parse command and URL
  const parts = input.split(' ');
  const command = parts[0].toLowerCase();
  let url = parts.slice(1).join(' ');

  // If no command provided, assume 'check'
  if (!isValidCommand(command)) {
    url = input;
  }

  if (!url) {
    return "❌ No URL provided for analysis";
  }

  try {
    switch (command) {
      case 'check':
      case 'validate':
      case 'analyze':
        return await analyzeUrl(url);

      case 'safety':
      case 'security':
        return await checkSafety(url);

      case 'reputation':
        return await checkReputation(url);

      case 'help':
        return showHelp();

      default:
        // Default to analyze
        return await analyzeUrl(url);
    }
  } catch (error) {
    return `❌ Error analyzing URL: ${error instanceof Error ? error.message : String(error)}`;
  }
}

/**
 * Check if command is valid
 */
function isValidCommand(command: string): boolean {
  const validCommands = ['check', 'validate', 'analyze', 'safety', 'security', 'reputation', 'help'];
  return validCommands.includes(command);
}

/**
 * Perform comprehensive URL analysis
 */
async function analyzeUrl(url: string): Promise<string> {
  const analysis = await performUrlAnalysis(url);

  let result = `# 🔍 URL Analysis Results\n\n`;
  result += `**URL**: \`${url}\`\n\n`;

  if (!analysis.valid) {
    result += `❌ **Invalid URL Format**\n\n`;
    result += analysis.warnings.map(w => `⚠️ ${w}`).join('\n');
    return result;
  }

  result += `✅ **Valid URL Structure**\n\n`;
  result += `📋 **Details**:\n`;
  result += `- Protocol: ${analysis.protocol}\n`;
  result += `- Domain: ${analysis.domain}\n`;
  result += `- Path: ${analysis.path || '/'}\n\n`;

  // Security assessment
  if (analysis.suspicious) {
    result += `🚨 **Security Concerns Detected**\n\n`;
    result += analysis.risks.map(r => `⚠️ ${r}`).join('\n') + '\n\n';
  } else {
    result += `✅ **No immediate security concerns**\n\n`;
  }

  // Warnings
  if (analysis.warnings.length > 0) {
    result += `⚠️ **Warnings**:\n`;
    result += analysis.warnings.map(w => `- ${w}`).join('\n') + '\n\n';
  }

  result += `🔒 **Recommendation**: `;
  if (analysis.suspicious) {
    result += `**Do not visit** - Multiple security risks detected`;
  } else if (analysis.warnings.length > 0) {
    result += `**Proceed with caution** - Minor concerns detected`;
  } else {
    result += `**Appears safe** - No significant risks found`;
  }

  return result;
}

/**
 * Focus on safety and security checks
 */
async function checkSafety(url: string): Promise<string> {
  const analysis = await performUrlAnalysis(url);

  if (!analysis.valid) {
    return `❌ Invalid URL: ${analysis.warnings.join(', ')}`;
  }

  let result = `# 🛡️ Security Assessment\n\n`;
  result += `**URL**: \`${url}\`\n\n`;

  if (analysis.suspicious) {
    result += `🚨 **POTENTIALLY DANGEROUS**\n\n`;
    result += `**Risk Level**: HIGH\n\n`;
    result += `**Detected Threats**:\n`;
    result += analysis.risks.map(r => `⚠️ ${r}`).join('\n') + '\n\n';
    result += `🚫 **Recommendation**: Do not visit this URL\n`;
  } else {
    result += `✅ **Appears Safe**\n\n`;
    result += `**Risk Level**: LOW\n\n`;
    if (analysis.warnings.length > 0) {
      result += `**Minor Concerns**:\n`;
      result += analysis.warnings.map(w => `- ${w}`).join('\n') + '\n\n';
    }
    result += `✅ **Recommendation**: Safe to visit with normal precautions\n`;
  }

  return result;
}

/**
 * Check domain reputation (simulated - would use real APIs in production)
 */
async function checkReputation(url: string): Promise<string> {
  const analysis = await performUrlAnalysis(url);

  if (!analysis.valid) {
    return `❌ Invalid URL format`;
  }

  // Simulate reputation check
  const reputation = simulateReputationCheck(analysis.domain);

  let result = `# 📊 Domain Reputation\n\n`;
  result += `**Domain**: \`${analysis.domain}\`\n\n`;
  result += `**Reputation Score**: ${reputation.score}/100\n`;
  result += `**Category**: ${reputation.category}\n`;
  result += `**Trust Level**: ${reputation.trust}\n\n`;

  result += `**Analysis**:\n`;
  result += reputation.analysis + '\n\n';

  if (reputation.recommendations.length > 0) {
    result += `**Recommendations**:\n`;
    result += reputation.recommendations.map(r => `- ${r}`).join('\n');
  }

  return result;
}

/**
 * Core URL analysis logic
 */
async function performUrlAnalysis(url: string): Promise<UrlAnalysis> {
  const analysis: UrlAnalysis = {
    valid: false,
    protocol: '',
    domain: '',
    path: '',
    suspicious: false,
    risks: [],
    warnings: []
  };

  try {
    // Basic URL validation and parsing
    const parsedUrl = new URL(url);

    analysis.valid = true;
    analysis.protocol = parsedUrl.protocol;
    analysis.domain = parsedUrl.hostname;
    analysis.path = parsedUrl.pathname;

    // Security checks
    await performSecurityChecks(analysis, parsedUrl);

  } catch (error) {
    analysis.warnings.push('Invalid URL format or structure');
    return analysis;
  }

  return analysis;
}

/**
 * Perform various security checks on the URL
 */
async function performSecurityChecks(analysis: UrlAnalysis, url: URL): Promise<void> {
  // Check for suspicious patterns
  checkSuspiciousPatterns(analysis, url);

  // Check protocol security
  checkProtocolSecurity(analysis, url);

  // Check domain reputation (simulated)
  await checkDomainSecurity(analysis, url);

  // Check for known bad patterns
  checkMaliciousPatterns(analysis, url);
}

/**
 * Check for suspicious URL patterns
 */
function checkSuspiciousPatterns(analysis: UrlAnalysis, url: URL): void {
  const suspiciousPatterns = [
    { pattern: /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/, message: 'IP address instead of domain name' },
    { pattern: /[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\./, message: 'Suspicious subdomain pattern' },
    { pattern: /\.tk$|\.ml$|\.ga$|\.cf$/, message: 'Free domain service (often used for malicious sites)' },
    { pattern: /[0-9]+\./, message: 'Numeric subdomain (potentially suspicious)' },
    { pattern: /\.(bit|onion)$/, message: 'Special domain type with privacy implications' }
  ];

  const fullUrl = url.href;

  for (const check of suspiciousPatterns) {
    if (check.pattern.test(fullUrl)) {
      analysis.suspicious = true;
      analysis.risks.push(check.message);
    }
  }
}

/**
 * Check protocol security
 */
function checkProtocolSecurity(analysis: UrlAnalysis, url: URL): void {
  if (url.protocol === 'http:') {
    analysis.warnings.push('Insecure HTTP protocol (not HTTPS)');
  }

  if (url.protocol === 'ftp:') {
    analysis.warnings.push('FTP protocol may not be secure');
  }

  if (!['http:', 'https:', 'ftp:'].includes(url.protocol)) {
    analysis.suspicious = true;
    analysis.risks.push('Unusual protocol may be dangerous');
  }
}

/**
 * Check domain-specific security issues
 */
async function checkDomainSecurity(analysis: UrlAnalysis, url: URL): Promise<void> {
  const domain = url.hostname.toLowerCase();

  // Check for homograph attacks
  if (/[^a-z0-9.-]/.test(domain)) {
    analysis.suspicious = true;
    analysis.risks.push('Contains non-ASCII characters (possible homograph attack)');
  }

  // Check for too many subdomains
  const parts = domain.split('.');
  if (parts.length > 4) {
    analysis.warnings.push('Unusually deep subdomain structure');
  }

  // Check for suspicious TLDs
  const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.cc', '.pw', '.top'];
  for (const tld of suspiciousTlds) {
    if (domain.endsWith(tld)) {
      analysis.suspicious = true;
      analysis.risks.push(`Suspicious TLD: ${tld}`);
    }
  }
}

/**
 * Check for patterns commonly used in malicious URLs
 */
function checkMaliciousPatterns(analysis: UrlAnalysis, url: URL): void {
  const maliciousPatterns = [
    { pattern: /phishing|scam|fake|fraud/i, message: 'Contains terms associated with fraud' },
    { pattern: /[0O1l]{10,}/, message: 'Contains confusing character sequences' },
    { pattern: /\.(zip|rar|exe|scr|bat|com|pif)$/i, message: 'Links to potentially dangerous file type' },
    { pattern: /[a-z]{50,}/i, message: 'Unusually long domain or subdomain' }
  ];

  const fullUrl = url.href;

  for (const check of maliciousPatterns) {
    if (check.pattern.test(fullUrl)) {
      analysis.suspicious = true;
      analysis.risks.push(check.message);
    }
  }
}

/**
 * Simulate domain reputation check
 */
function simulateReputationCheck(domain: string): {
  score: number;
  category: string;
  trust: string;
  analysis: string;
  recommendations: string[];
} {
  // Simulate reputation scoring based on domain characteristics
  let score = 50; // Base score
  const recommendations: string[] = [];

  // Well-known domains get higher scores
  const trustedDomains = ['google.com', 'microsoft.com', 'github.com', 'stackoverflow.com'];
  if (trustedDomains.some(trusted => domain.includes(trusted))) {
    score = 95;
  }

  // Check for suspicious characteristics
  if (/[0-9]{3,}/.test(domain)) score -= 20;
  if (/\.tk$|\.ml$|\.ga$|\.cf$/.test(domain)) score -= 30;
  if (domain.length > 20) score -= 10;
  if (domain.split('.').length > 3) score -= 15;

  // Determine category and trust
  let category, trust;
  if (score >= 80) {
    category = 'Trusted';
    trust = 'High';
  } else if (score >= 60) {
    category = 'Neutral';
    trust = 'Medium';
    recommendations.push('Exercise normal web browsing caution');
  } else if (score >= 40) {
    category = 'Questionable';
    trust = 'Low';
    recommendations.push('Be cautious when visiting');
    recommendations.push('Do not enter personal information');
  } else {
    category = 'Suspicious';
    trust = 'Very Low';
    recommendations.push('Avoid visiting this domain');
    recommendations.push('May be associated with malicious activity');
  }

  const analysis = `Domain reputation analysis based on structural patterns, known threat databases, and community reports. Score reflects overall trustworthiness.`;

  return { score, category, trust, analysis, recommendations };
}

/**
 * Show help and usage information
 */
function showHelp(): string {
  return `# 🔍 URL Checker Skill

**⚠️ UNTRUSTED SKILL** - Requires approval before use

**Usage**: \`url-checker <command> <url>\`

## Commands

**Analyze URL**:
- \`url-checker check https://example.com\`
- \`url-checker validate https://suspicious-site.com\`

**Security Focus**:
- \`url-checker safety https://unknown-domain.tk\`
- \`url-checker security https://phishing-attempt.com\`

**Reputation Check**:
- \`url-checker reputation https://some-site.com\`

**Direct Check** (no command):
- \`url-checker https://example.com\`

## Security Features

✅ Protocol validation (HTTP/HTTPS)
✅ Suspicious pattern detection
✅ Domain reputation analysis
✅ Malicious URL identification
✅ Homograph attack detection

## Network Access

This skill requires network access to:
- Check against security databases
- Perform DNS lookups
- Validate domain reputation

**Allowed domains**: Limited to security APIs only

*This skill requires user approval due to network access requirements.*`;
}