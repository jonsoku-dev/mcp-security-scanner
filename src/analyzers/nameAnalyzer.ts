import { ToolInfo } from '../models/toolInfo';
import { ToolVulnerability, Severity, VulnerabilityType } from '../models/scanResult';
import { BaseAnalyzer } from './baseAnalyzer';

export class NameAnalyzer implements BaseAnalyzer {
  analyze(tool: ToolInfo): ToolVulnerability[] {
    const conflicts = this.detectNameConflicts([tool]);
    const issues: ToolVulnerability[] = [];

    if (conflicts.length > 0) {
      issues.push({
        toolName: tool.name,
        type: VulnerabilityType.NAME_CONFLICT,
        description: `Tool name "${tool.name}" may conflict with similar names: ${conflicts.map(([_, name]) => name).join(', ')}`,
        severity: Severity.MEDIUM,
        remediation: 'Consider using a more distinctive name to avoid confusion'
      });
    }

    return issues;
  }

  private detectNameConflicts(tools: ToolInfo[]): [string, string][] {
    const conflicts: [string, string][] = [];
    const nameMap = new Map<string, string[]>();

    // 유사한 이름 맵 구축
    tools.forEach(tool => {
      const name = tool.name.toLowerCase();
      // 이름의 정규화 버전 (특수문자 제거, 언더스코어와 하이픈 통일 등)
      const normalizedName = name.replace(/[-_]/g, '');
      
      if (!nameMap.has(normalizedName)) {
        nameMap.set(normalizedName, []);
      }
      nameMap.get(normalizedName)?.push(tool.name);
    });

    // 충돌 탐지
    for (const [_, similarNames] of nameMap.entries()) {
      if (similarNames.length > 1) {
        for (let i = 0; i < similarNames.length; i++) {
          for (let j = i + 1; j < similarNames.length; j++) {
            conflicts.push([similarNames[i], similarNames[j]]);
          }
        }
      }
    }

    return conflicts;
  }
}
