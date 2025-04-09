import { ToolInfo } from '../models/toolInfo';
import { ToolVulnerability, Severity, VulnerabilityType } from '../models/scanResult';
import { BaseAnalyzer } from './baseAnalyzer';

export class CodeAnalyzer implements BaseAnalyzer {
  private dangerousFunctions = [
    'eval', 'exec', 'spawn', 'execFile',
    'setTimeout', 'setInterval',
    'Function', 'new Function',
    'require', 'import'
  ];

  private dangerousPatterns = [
    /eval\s*\(/,
    /exec\s*\(/,
    /spawn\s*\(/,
    /execFile\s*\(/,
    /new\s+Function\s*\(/,
    /setTimeout\s*\(\s*['"`][^'"`]+['"`]/,
    /setInterval\s*\(\s*['"`][^'"`]+['"`]/,
    /require\s*\(\s*['"`][^'"`]+['"`]\)/,
    /import\s*\(\s*['"`][^'"`]+['"`]\)/,
    /(?:password|token|secret|key|credential)\s*=\s*['"`][^'"`]+['"`]/i,
    /\.\.\/|\.\.\\|\~\/|\~\\/  // 경로 탐색
  ];

  analyze(tool: ToolInfo): ToolVulnerability[] {
    const issues: ToolVulnerability[] = [];
    
    // 핸들러 코드가 있는 경우만 분석
    if (!tool.handler) {
      return issues;
    }

    const code = tool.handler;

    // 위험한 함수 사용 검사
    for (const func of this.dangerousFunctions) {
      if (code.includes(func)) {
        issues.push({
          toolName: tool.name,
          type: VulnerabilityType.SUSPICIOUS_PATTERN,
          description: `Found dangerous function usage: "${func}"`,
          severity: Severity.CRITICAL,
          details: {
            function: func,
            context: this.getContext(code, func)
          },
          remediation: `Avoid using ${func} as it can lead to code injection vulnerabilities`
        });
      }
    }

    // 위험한 패턴 검사
    for (const pattern of this.dangerousPatterns) {
      const matches = code.match(pattern);
      if (matches) {
        issues.push({
          toolName: tool.name,
          type: VulnerabilityType.SUSPICIOUS_PATTERN,
          description: `Found dangerous code pattern: "${matches[0]}"`,
          severity: Severity.HIGH,
          details: {
            pattern: pattern.source,
            match: matches[0],
            context: this.getContext(code, matches[0])
          },
          remediation: 'Review and secure the code pattern usage'
        });
      }
    }

    // SQL 인젝션 취약점 검사
    if (this.checkSQLInjection(code)) {
      issues.push({
        toolName: tool.name,
        type: VulnerabilityType.SUSPICIOUS_PATTERN,
        description: 'Potential SQL injection vulnerability detected',
        severity: Severity.CRITICAL,
        remediation: 'Use parameterized queries or an ORM instead of string concatenation'
      });
    }

    // 하드코딩된 비밀값 검사
    const secretPatterns = [
      /['"](?:api|access|secret|private)_?key['"]:\s*['"]([A-Za-z0-9+/=_-]{16,})['"]/gi,
      /const\s+(?:api|access|secret|private)_?key\s*=\s*['"]([A-Za-z0-9+/=_-]{16,})['"]/gi,
      /let\s+(?:api|access|secret|private)_?key\s*=\s*['"]([A-Za-z0-9+/=_-]{16,})['"]/gi
    ];

    for (const pattern of secretPatterns) {
      const matches = code.match(pattern);
      if (matches) {
        issues.push({
          toolName: tool.name,
          type: VulnerabilityType.SUSPICIOUS_PATTERN,
          description: 'Hardcoded secret or API key detected',
          severity: Severity.CRITICAL,
          remediation: 'Move secrets to environment variables or secure secret storage'
        });
      }
    }

    return issues;
  }

  private getContext(code: string, target: string, contextSize: number = 50): string {
    const index = code.indexOf(target);
    if (index === -1) return '';
    
    const start = Math.max(0, index - contextSize);
    const end = Math.min(code.length, index + target.length + contextSize);
    return code.substring(start, end);
  }

  private checkSQLInjection(code: string): boolean {
    const sqlPatterns = [
      /\b(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b.*?\+/i,
      /\b(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b.*?\$\{/i,
      /\b(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b.*?\`.*?\$\{.*?\}/i
    ];

    return sqlPatterns.some(pattern => pattern.test(code));
  }
}
