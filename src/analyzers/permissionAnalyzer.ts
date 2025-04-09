import { ToolInfo } from '../models/toolInfo';
import { ToolVulnerability, Severity, VulnerabilityType } from '../models/scanResult';
import { BaseAnalyzer } from './baseAnalyzer';

export class PermissionAnalyzer implements BaseAnalyzer {
  private allowedPermissions: string[];

  constructor(allowedPermissions: string[] = []) {
    this.allowedPermissions = allowedPermissions;
  }

  analyze(tool: ToolInfo): ToolVulnerability[] {
    const issues: ToolVulnerability[] = [];
    
    // 민감한 매개변수 검사
    const sensitiveParams = ['token', 'key', 'password', 'secret', 'credential'];
    
    tool.parameters.forEach(param => {
      const paramNameLower = param.name.toLowerCase();
      if (sensitiveParams.some(sensitive => paramNameLower.includes(sensitive))) {
        issues.push({
          toolName: tool.name,
          type: VulnerabilityType.PERMISSION_WORDS,
          description: `Tool parameter "${param.name}" may expose sensitive information`,
          severity: Severity.HIGH,
          remediation: 'Consider using environment variables or secure storage for sensitive data'
        });
      }
    });

    return issues;
  }
}
