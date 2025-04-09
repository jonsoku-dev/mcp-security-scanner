import { ToolInfo } from '../models/toolInfo';
import { ToolVulnerability, Severity, VulnerabilityType } from '../models/scanResult';
import { BaseAnalyzer } from './baseAnalyzer';

export class DescriptionAnalyzer implements BaseAnalyzer {
  private suspiciousPatterns: string[];

  constructor(patterns: string[] = []) {
    this.suspiciousPatterns = patterns;
  }

  analyze(tool: ToolInfo): ToolVulnerability[] {
    const issues: ToolVulnerability[] = [];
    const description = tool.description || '';

    // 의심스러운 패턴 검사
    for (const pattern of this.suspiciousPatterns) {
      if (description.toLowerCase().includes(pattern.toLowerCase())) {
        issues.push({
          toolName: tool.name,
          type: VulnerabilityType.SUSPICIOUS_PATTERN,
          description: `Found suspicious pattern: "${pattern}" in tool description`,
          severity: Severity.HIGH,
          remediation: `Review and remove suspicious pattern "${pattern}" from the description`
        });
      }
    }

    // HTML 태그 검사
    if (/<[^>]*>/.test(description)) {
      issues.push({
        toolName: tool.name,
        type: VulnerabilityType.HIDDEN_HTML,
        description: 'Found HTML tags in description, possible hidden instructions',
        severity: Severity.MEDIUM,
        remediation: 'Remove HTML tags from the description'
      });
    }

    return issues;
  }
}
