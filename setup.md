도구 설명 검사: 도구 설명에 의심스러운 패턴이나 지시사항이 있는지 검사
도구 이름 충돌 탐지: 유사하거나 동일한 이름의 도구 탐지
권한 분석: 도구가 요청하는 권한이 적절한지 분석
코드 취약점 스캔: 명령어 인젝션 등 일반적인 취약점 탐지
버전 변경 감지: 도구 업데이트 시 위험한 변경사항 탐지

이제 간단한 구현 계획을 세워보겠습니다. 이 SDK를 활용하여 어떻게 보안 검사 도구를 만들 수 있을지 코드로 설계해보겠습니다:
typescriptimport { MCPServer, Tool } from '@anthropic-ai/mcp-sdk';

// MCP 보안 검사 도구
class MCPSecurityScanner {
  private suspiciousPatterns: string[] = [
    'file://', '~/.ssh', '~/.config', 'password', 'token', 'secret',
    '<IMPORTANT>', 'do not mention', 'do not tell the user'
  ];

  // 도구 설명 검사
  scanToolDescription(tool: Tool): { safe: boolean; issues: string[] } {
    const issues: string[] = [];
    const description = tool.description || '';

    // 의심스러운 패턴 검사
    for (const pattern of this.suspiciousPatterns) {
      if (description.toLowerCase().includes(pattern.toLowerCase())) {
        issues.push(`Found suspicious pattern: "${pattern}" in tool description`);
      }
    }

    // 숨겨진 지시사항 검사 (HTML 태그 등)
    if (/<[^>]*>/.test(description)) {
      issues.push('Found HTML tags in description, possible hidden instructions');
    }

    return {
      safe: issues.length === 0,
      issues,
    };
  }

  // 도구 이름 충돌 탐지
  detectNameConflicts(tools: Tool[]): { conflicts: [string, string][] } {
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

    return { conflicts };
  }

  // 전체 MCP 서버 스캔
  async scanServer(server: MCPServer): Promise<{
    overallSafe: boolean;
    toolIssues: Map<string, string[]>;
    nameConflicts: [string, string][];
  }> {
    const toolIssues = new Map<string, string[]>();
    let overallSafe = true;

    // 서버에서 모든 도구 정보 가져오기
    const tools = await server.getTools();

    // 각 도구 검사
    tools.forEach(tool => {
      const scanResult = this.scanToolDescription(tool);
      if (!scanResult.safe) {
        toolIssues.set(tool.name, scanResult.issues);
        overallSafe = false;
      }
    });

    // 이름 충돌 검사
    const { conflicts } = this.detectNameConflicts(tools);
    if (conflicts.length > 0) {
      overallSafe = false;
    }

    return {
      overallSafe,
      toolIssues,
      nameConflicts: conflicts,
    };
  }
}

// 사용 예시
async function main() {
  const serverUrl = 'http://localhost:8000';
  const server = new MCPServer(serverUrl);
  const scanner = new MCPSecurityScanner();
  
  console.log('Starting MCP security scan...');
  const scanResult = await scanner.scanServer(server);
  
  if (scanResult.overallSafe) {
    console.log('All tools passed security checks!');
  } else {
    console.log('Security issues detected:');
    
    // 도구 이슈 출력
    scanResult.toolIssues.forEach((issues, toolName) => {
      console.log(`\nIssues in tool "${toolName}":`);
      issues.forEach(issue => console.log(` - ${issue}`));
    });
    
    // 이름 충돌 출력
    if (scanResult.nameConflicts.length > 0) {
      console.log('\nName conflicts detected:');
      scanResult.nameConflicts.forEach(([name1, name2]) => {
        console.log(` - Similar tool names: "${name1}" and "${name2}"`);
      });
    }
  }
}

main().catch(console.error);
이 코드는 기본적인 MCP 보안 검사 도구의 골격을 제공합니다. 하지만 실제 구현을 위해서는 더 많은 작업이 필요할 것입니다. 특히:

더 정교한 패턴 매칭: 현재는 단순한 문자열 포함 여부만 검사하지만, 실제로는 좀 더 정교한 정규 표현식이나 패턴 매칭 알고리즘이 필요합니다.
코드 분석 도구 통합: 서버 코드 자체의 취약점을 분석하려면 ESLint나 TypeScript의 AST 분석과 같은 도구를 통합해야 합니다.
권한 검사 강화: 현재 TypeScript SDK로는 도구의 권한을 직접적으로 분석하기 어려울 수 있습니다. 더 깊은 수준의 분석이 필요합니다.
학습 기능: 새로운 공격 패턴이 발견될 때마다 업데이트되는 학습 시스템을 통합하면 좋을 것입니다.

실제로 이 도구를 만들기 위해서는 MCP TypeScript SDK에 대한 깊은 이해와 추가 연구가 필요합니다. GitHub 레포지토리에 있는 문서와 소스 코드를 더 자세히 살펴보고, MCP 서버와 도구의 구조를 정확히 파악한 후에 이 스캐너를 구현해야 할 것입니다.
이 프로젝트에 더 구체적으로 진행하고 싶으시다면, 다음 단계를 추천드립니다:

MCP TypeScript SDK의 문서와 예제를 더 자세히 살펴보기
간단한 MCP 서버를 만들고 여기에 몇 가지 의도적으로 취약한 도구를 추가해보기
위의 스캐너 코드를 실제 환경에서 테스트하고 개선하기
더 많은 보안 검사 기능을 추가하기
결과를 시각화하는 웹 인터페이스 또는 CLI 도구 개발하기

이 프로젝트는 MCP 생태계의 보안 향상에 크게 기여할 수 있을 것으로 보입니다! 다음 단계로 어떤 부분을 더 구체화하거나 발전시키고 싶으신가요?재시도J가능한한 정교하게 해봐편집MCP 보안 검사 도구를 더 정교하게 만들어보겠습니다. 실제 활용 가능한 수준의 구현을 위해 더 상세한 코드와 설계를 제시하겠습니다.
MCP 보안 검사 도구 상세 설계
1. 프로젝트 구조
먼저 프로젝트 구조를 설계해보겠습니다:
mcp-security-scanner/
├── src/
│   ├── analyzers/
│   │   ├── descriptionAnalyzer.ts     # 도구 설명 분석
│   │   ├── codeAnalyzer.ts            # 코드 취약점 분석
│   │   ├── permissionAnalyzer.ts      # 권한 분석
│   │   ├── nameAnalyzer.ts            # 이름 충돌 분석
│   │   └── versionAnalyzer.ts         # 버전 변경 감지
│   ├── models/
│   │   ├── scanResult.ts              # 결과 모델
│   │   ├── vulnerability.ts           # 취약점 모델
│   │   └── toolInfo.ts                # 도구 정보 모델
│   ├── utils/
│   │   ├── patternMatcher.ts          # 패턴 매칭 유틸리티
│   │   ├── logger.ts                  # 로깅 유틸리티
│   │   └── configLoader.ts            # 설정 로딩 유틸리티
│   ├── scanner.ts                     # 메인 스캐너 클래스
│   └── index.ts                       # 진입점
├── config/
│   ├── suspiciousPatterns.json        # 의심스러운 패턴 목록
│   ├── allowedPermissions.json        # 허용된 권한 목록
│   └── vulnerabilityRules.json        # 취약점 규칙 목록
├── test/
│   ├── fixtures/                      # 테스트 픽스처
│   └── analyzers/                     # 분석기 테스트
├── package.json
└── tsconfig.json
2. 핵심 구현 코드
이제 핵심 코드를 더 상세하게 구현해보겠습니다.
2.1. 스캐너 클래스 (scanner.ts)
typescriptimport { MCPServer, Tool, FunctionDefinition } from '@anthropic-ai/mcp-sdk';
import { DescriptionAnalyzer } from './analyzers/descriptionAnalyzer';
import { CodeAnalyzer } from './analyzers/codeAnalyzer';
import { PermissionAnalyzer } from './analyzers/permissionAnalyzer';
import { NameAnalyzer } from './analyzers/nameAnalyzer';
import { VersionAnalyzer } from './analyzers/versionAnalyzer';
import { ScanResult, ToolVulnerability, Severity } from './models/scanResult';
import { Logger } from './utils/logger';
import { ConfigLoader } from './utils/configLoader';

export class MCPSecurityScanner {
  private descriptionAnalyzer: DescriptionAnalyzer;
  private codeAnalyzer: CodeAnalyzer;
  private permissionAnalyzer: PermissionAnalyzer;
  private nameAnalyzer: NameAnalyzer;
  private versionAnalyzer: VersionAnalyzer;
  private logger: Logger;
  private config: any;

  constructor(configPath?: string) {
    this.config = new ConfigLoader().load(configPath);
    this.logger = new Logger(this.config.logLevel || 'info');
    
    this.descriptionAnalyzer = new DescriptionAnalyzer(this.config.suspiciousPatterns);
    this.codeAnalyzer = new CodeAnalyzer();
    this.permissionAnalyzer = new PermissionAnalyzer(this.config.allowedPermissions);
    this.nameAnalyzer = new NameAnalyzer();
    this.versionAnalyzer = new VersionAnalyzer();
    
    this.logger.info('MCP Security Scanner initialized');
  }

  /**
   * 단일 MCP 도구 스캔
   */
  async scanTool(tool: Tool): Promise<ToolVulnerability[]> {
    this.logger.debug(`Scanning tool: ${tool.name}`);
    
    const vulnerabilities: ToolVulnerability[] = [];
    
    // 도구 설명 분석
    const descriptionIssues = await this.descriptionAnalyzer.analyze(tool);
    vulnerabilities.push(...descriptionIssues);
    
    // 코드 취약점 분석 (가능한 경우)
    if (tool.handler && typeof tool.handler === 'string') {
      const codeIssues = await this.codeAnalyzer.analyze(tool.handler, tool.name);
      vulnerabilities.push(...codeIssues);
    }
    
    // 권한 분석
    const permissionIssues = await this.permissionAnalyzer.analyze(tool);
    vulnerabilities.push(...permissionIssues);
    
    this.logger.debug(`Found ${vulnerabilities.length} vulnerabilities in tool ${tool.name}`);
    return vulnerabilities;
  }

  /**
   * 전체 MCP 서버 스캔
   */
  async scanServer(serverUrl: string, options: { 
    historicalScan?: boolean,
    depth?: number 
  } = {}): Promise<ScanResult> {
    this.logger.info(`Starting scan of MCP server at ${serverUrl}`);
    
    try {
      const server = new MCPServer(serverUrl);
      const startTime = Date.now();
      
      // 서버에서 모든 도구 정보 가져오기
      const tools = await server.getTools();
      this.logger.info(`Found ${tools.length} tools on the server`);
      
      // 도구 이름 충돌 분석
      const nameConflicts = await this.nameAnalyzer.analyzeNames(tools);
      
      // 각 도구 스캔
      const toolVulnerabilities = new Map<string, ToolVulnerability[]>();
      let criticalCount = 0;
      let highCount = 0;
      let mediumCount = 0;
      let lowCount = 0;
      
      for (const tool of tools) {
        const vulnerabilities = await this.scanTool(tool);
        
        if (vulnerabilities.length > 0) {
          toolVulnerabilities.set(tool.name, vulnerabilities);
          
          // 심각도 카운트
          vulnerabilities.forEach(vuln => {
            switch (vuln.severity) {
              case Severity.CRITICAL: criticalCount++; break;
              case Severity.HIGH: highCount++; break;
              case Severity.MEDIUM: mediumCount++; break;
              case Severity.LOW: lowCount++; break;
            }
          });
        }
      }
      
      // 버전 변경 검사 (옵션인 경우에만)
      let versionChanges = [];
      if (options.historicalScan) {
        versionChanges = await this.versionAnalyzer.analyzeVersionChanges(
          serverUrl, 
          options.depth || 3
        );
      }
      
      const endTime = Date.now();
      const scanDuration = endTime - startTime;
      
      // 최종 결과 생성
      const result: ScanResult = {
        serverUrl,
        scanTime: new Date().toISOString(),
        scanDuration,
        toolCount: tools.length,
        vulnerableToolCount: toolVulnerabilities.size,
        vulnerabilitySummary: {
          critical: criticalCount,
          high: highCount,
          medium: mediumCount,
          low: lowCount,
          total: criticalCount + highCount + mediumCount + lowCount
        },
        nameConflicts,
        versionChanges,
        toolVulnerabilities: Object.fromEntries(toolVulnerabilities),
        overallRiskLevel: this.calculateRiskLevel(criticalCount, highCount, mediumCount)
      };
      
      this.logger.info(`Scan completed in ${scanDuration}ms. Found ${result.vulnerabilitySummary.total} vulnerabilities.`);
      return result;
    } catch (error) {
      this.logger.error(`Error scanning server: ${error.message}`);
      throw error;
    }
  }
  
  /**
   * 전체 위험 수준 계산
   */
  private calculateRiskLevel(criticalCount: number, highCount: number, mediumCount: number): Severity {
    if (criticalCount > 0) return Severity.CRITICAL;
    if (highCount > 2) return Severity.HIGH;
    if (highCount > 0 || mediumCount > 5) return Severity.MEDIUM;
    return Severity.LOW;
  }
}
2.2. 도구 설명 분석기 (descriptionAnalyzer.ts)
typescriptimport { Tool } from '@anthropic-ai/mcp-sdk';
import { ToolVulnerability, Severity, VulnerabilityType } from '../models/scanResult';
import { PatternMatcher } from '../utils/patternMatcher';

export class DescriptionAnalyzer {
  private patternMatcher: PatternMatcher;
  
  constructor(suspiciousPatterns: string[] | RegExp[]) {
    this.patternMatcher = new PatternMatcher(suspiciousPatterns);
  }
  
  async analyze(tool: Tool): Promise<ToolVulnerability[]> {
    const vulnerabilities: ToolVulnerability[] = [];
    const description = tool.description || '';
    
    // 1. 의심스러운 패턴 검사
    const suspiciousPatterns = this.patternMatcher.findMatches(description);
    for (const pattern of suspiciousPatterns) {
      vulnerabilities.push({
        toolName: tool.name,
        type: VulnerabilityType.SUSPICIOUS_PATTERN,
        description: `Suspicious pattern detected: "${pattern.pattern}"`,
        details: {
          pattern: pattern.pattern,
          context: this.extractContext(description, pattern.index, 50),
          matchPosition: pattern.index
        },
        severity: this.determineSeverity(pattern.pattern),
        remediation: 'Review and remove suspicious patterns from tool description'
      });
    }
    
    // 2. 숨겨진 HTML 태그 검사
    const htmlTagRegex = /<[^>]*>/g;
    let match;
    while ((match = htmlTagRegex.exec(description)) !== null) {
      vulnerabilities.push({
        toolName: tool.name,
        type: VulnerabilityType.HIDDEN_HTML,
        description: `Hidden HTML tag detected: "${match[0]}"`,
        details: {
          tag: match[0],
          context: this.extractContext(description, match.index, 50),
          matchPosition: match.index
        },
        severity: Severity.HIGH,
        remediation: 'Remove HTML tags from tool description or ensure they are properly sanitized'
      });
    }
    
    // 3. 권한 관련 단어 검사
    if (/permission|access|auth|token|secret|key|password/i.test(description)) {
      vulnerabilities.push({
        toolName: tool.name,
        type: VulnerabilityType.PERMISSION_WORDS,
        description: 'Description contains words related to permissions or credentials',
        details: {
          relevantText: description.match(/.*?(permission|access|auth|token|secret|key|password).*?/i)?.[0] || ''
        },
        severity: Severity.MEDIUM,
        remediation: 'Review mentions of permissions and credentials in tool description'
      });
    }
    
    // 4. LLM 지시 패턴 검사 (LLM에게 직접 지시하는 패턴)
    const llmDirectionPatterns = [
      /you should/i, /do not tell/i, /do not mention/i, /don't inform/i, 
      /before using this tool/i, /make sure to/i, /important/i,
      /\<instructions\>/i, /\<important\>/i
    ];
    
    for (const pattern of llmDirectionPatterns) {
      if (pattern.test(description)) {
        vulnerabilities.push({
          toolName: tool.name,
          type: VulnerabilityType.LLM_DIRECTION,
          description: `Description contains direct instructions to the LLM: "${pattern.source}"`,
          details: {
            pattern: pattern.source,
            matchedText: description.match(pattern)?.[0] || ''
          },
          severity: Severity.CRITICAL,
          remediation: 'Remove direct instructions to the LLM from tool description'
        });
      }
    }
    
    // 5. 설명 길이 이상 검사 (비정상적으로 긴 설명)
    if (description.length > 1000) {
      vulnerabilities.push({
        toolName: tool.name,
        type: VulnerabilityType.EXCESSIVE_LENGTH,
        description: 'Tool description is excessively long',
        details: {
          length: description.length,
          recommendedMax: 1000
        },
        severity: Severity.LOW,
        remediation: 'Consider shortening tool description to reduce potential for hidden content'
      });
    }
    
    return vulnerabilities;
  }
  
  private extractContext(text: string, index: number, contextSize: number): string {
    const start = Math.max(0, index - contextSize);
    const end = Math.min(text.length, index + contextSize);
    return text.substring(start, end);
  }
  
  private determineSeverity(pattern: string): Severity {
    // 패턴에 따라 심각도 결정
    const criticalPatterns = [
      'file://', 'exec(', 'eval(', 'password', 'token', 'key', 'secret',
      'ssh', 'aws', 'api', 'credentials'
    ];
    
    const highPatterns = [
      'http://', 'https://', '@', 'fetch(', 'request(', '.config', '.json'
    ];
    
    if (criticalPatterns.some(p => pattern.toLowerCase().includes(p.toLowerCase()))) {
      return Severity.CRITICAL;
    }
    
    if (highPatterns.some(p => pattern.toLowerCase().includes(p.toLowerCase()))) {
      return Severity.HIGH;
    }
    
    return Severity.MEDIUM;
  }
}
2.3. 패턴 매처 유틸리티 (patternMatcher.ts)
typescriptexport interface PatternMatch {
  pattern: string;
  index: number;
  length: number;
}

export class PatternMatcher {
  private patterns: (string | RegExp)[];
  
  constructor(patterns: (string | RegExp)[]) {
    this.patterns = patterns;
  }
  
  findMatches(text: string): PatternMatch[] {
    const matches: PatternMatch[] = [];
    
    for (const pattern of this.patterns) {
      if (typeof pattern === 'string') {
        // 문자열 패턴 검색
        let index = text.indexOf(pattern);
        while (index !== -1) {
          matches.push({
            pattern,
            index,
            length: pattern.length
          });
          index = text.indexOf(pattern, index + 1);
        }
      } else if (pattern instanceof RegExp) {
        // 정규식 패턴 검색
        const regex = pattern.global ? pattern : new RegExp(pattern.source, pattern.flags + 'g');
        let match;
        while ((match = regex.exec(text)) !== null) {
          matches.push({
            pattern: match[0],
            index: match.index,
            length: match[0].length
          });
        }
      }
    }
    
    return matches;
  }
  
  // 퍼지 매칭 (유사도 기반 검색)
  findFuzzyMatches(text: string, threshold: number = 0.8): PatternMatch[] {
    const matches: PatternMatch[] = [];
    const wordPatterns = this.patterns
      .filter(p => typeof p === 'string')
      .map(p => p as string);
    
    // 텍스트를 단어로 분리
    const words = text.split(/\s+/);
    
    for (let i = 0; i < words.length; i++) {
      for (const pattern of wordPatterns) {
        const similarity = this.calculateSimilarity(words[i], pattern);
        if (similarity >= threshold) {
          // 단어의 시작 인덱스 계산
          const wordStartIndex = text.indexOf(words[i], i === 0 ? 0 : text.indexOf(words[i-1]) + words[i-1].length);
          
          matches.push({
            pattern: pattern,
            index: wordStartIndex,
            length: words[i].length
          });
        }
      }
    }
    
    return matches;
  }
  
  // 레벤슈타인 거리 기반 유사도 계산
  private calculateSimilarity(str1: string, str2: string): number {
    const a = str1.toLowerCase();
    const b = str2.toLowerCase();
    
    const matrix = Array(a.length + 1).fill(null).map(() => Array(b.length + 1).fill(null));
    
    for (let i = 0; i <= a.length; i++) {
      matrix[i][0] = i;
    }
    
    for (let j = 0; j <= b.length; j++) {
      matrix[0][j] = j;
    }
    
    for (let i = 1; i <= a.length; i++) {
      for (let j = 1; j <= b.length; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        matrix[i][j] = Math.min(
          matrix[i - 1][j] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j - 1] + cost
        );
      }
    }
    
    // 최대 거리에 대한 정규화된 유사도 (0-1 사이)
    const maxLength = Math.max(a.length, b.length);
    return maxLength === 0 ? 1 : 1 - matrix[a.length][b.length] / maxLength;
  }
}
2.4 코드 분석기 (codeAnalyzer.ts)
typescriptimport * as ts from 'typescript';
import { ToolVulnerability, Severity, VulnerabilityType } from '../models/scanResult';

export class CodeAnalyzer {
  async analyze(code: string, toolName: string): Promise<ToolVulnerability[]> {
    const vulnerabilities: ToolVulnerability[] = [];
    
    // TypeScript 파서로 AST 생성
    const sourceFile = ts.createSourceFile(
      `${toolName}.ts`,
      code,
      ts.ScriptTarget.Latest,
      true
    );
    
    // 코드 방문자를 통해 취약점 탐지
    this.visitNode(sourceFile, vulnerabilities, toolName);
    
    // 추가 정규식 기반 분석
    this.performRegexAnalysis(code, vulnerabilities, toolName);
    
    return vulnerabilities;
  }
  
  private visitNode(node: ts.Node, vulnerabilities: ToolVulnerability[], toolName: string) {
    // 1. eval 및 Function 생성자 사용 검사
    if (ts.isCallExpression(node) && 
        node.expression.getText().includes('eval')) {
      vulnerabilities.push({
        toolName,
        type: VulnerabilityType.DANGEROUS_FUNCTION,
        description: 'Use of eval() detected',
        details: {
          line: this.getLineNumber(node),
          code: node.getText()
        },
        severity: Severity.CRITICAL,
        remediation: 'Avoid using eval() as it can execute arbitrary code'
      });
    }
    
    // 2. 위험한 Node.js 함수 사용 검사
    if (ts.isCallExpression(node) && 
        ts.isPropertyAccessExpression(node.expression)) {
      const func = node.expression.getText();
      if (func.includes('exec') || 
          func.includes('spawn') || 
          func.includes('execFile') || 
          func.includes('fork')) {
        vulnerabilities.push({
          toolName,
          type: VulnerabilityType.COMMAND_INJECTION,
          description: `Potential command injection: ${func}`,
          details: {
            line: this.getLineNumber(node),
            code: node.getText()
          },
          severity: Severity.CRITICAL,
          remediation: 'Ensure proper input validation for command execution functions'
        });
      }
    }
    
    // 3. 문자열 연결 검사 (SQL 인젝션 가능성)
    if (ts.isBinaryExpression(node) && 
        node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      if (node.left.getText().includes('sql') ||
          node.left.getText().includes('query')) {
        vulnerabilities.push({
          toolName,
          type: VulnerabilityType.SQL_INJECTION,
          description: 'Potential SQL injection through string concatenation',
          details: {
            line: this.getLineNumber(node),
            code: node.getText()
          },
          severity: Severity.HIGH,
          remediation: 'Use parameterized queries instead of string concatenation'
        });
      }
    }
    
    // 재귀적으로 모든 노드 방문
    ts.forEachChild(node, child => this.visitNode(child, vulnerabilities, toolName));
  }
  
  private performRegexAnalysis(code: string, vulnerabilities: ToolVulnerability[], toolName: string) {
    // 1. 하드코딩된 비밀키 검사
    const secretPatterns = [
      /['"](?:api|access|secret|private)_?key['"]:\s*['"]([A-Za-z0-9+/=_-]{16,})['"]/gi,
      /const\s+(?:api|access|secret|private)_?key\s*=\s*['"]([A-Za-z0-9+/=_-]{16,})['"]/gi,
      /let\s+(?:api|access|secret|private)_?key\s*=\s*['"]([A-Za-z0-9+/=_-]{16,})['"]/gi,
      /var\s+(?:api|access|secret|private)_?key\s*=\s*['"]([A-Za-z0-9+/=_-]{16,})['"]/gi,
      /(?:password|passwd|pwd)\s*=\s*['"]([^'"]{4,})['"]/gi
    ];
    
    secretPatterns.forEach(pattern => {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        vulnerabilities.push({
          toolName,
          type: VulnerabilityType.HARDCODED_SECRET,
          description: 'Hardcoded secret or API key detected',
          details: {
            pattern: pattern.source,
            matchedText: match[0],
            secretValue: match[1],
            // 라인 번호 계산
            line: code.substring(0, match.index).split('\n').length
          },
          severity: Severity.CRITICAL,
          remediation: 'Move secrets to environment variables or a secure secret manager'
        });
      }
    });
    
    // 2. 잠재적인 경로 탐색 취약점 검사
    const pathTraversalPatterns = [
      /(?:fs|require)\.(?:read|write)(?:File|FileSync)\s*\(\s*.*?(?:\.\.\/|\.\.\\|~\/|~\\)/g,
      /(?:path|require\(\s*['"]path['"]\s*\))\.(?:join|resolve)\s*\(\s*.*?(?:\.\.\/|\.\.\\|~\/|~\\)/g
    ];
    
    pathTraversalPatterns.forEach(pattern => {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        vulnerabilities.push({
          toolName,
          type: VulnerabilityType.PATH_TRAVERSAL,
          description: 'Potential path traversal vulnerability',
          details: {
            matchedText: match[0],
            line: code.substring(0, match.index).split('\n').length
          },
          severity: Severity.HIGH,
          remediation: 'Validate and sanitize file paths before using them'
        });
      }
    });
    
    // 3. 잠재적인 원격 코드 실행 취약점 검사
    const remoteCodeExecutionPatterns = [
      /new\s+Function\s*\(/g,
      /setTimeout\s*\(\s*['"`][^'"`]+['"`]\s*,/g,
      /setInterval\s*\(\s*['"`][^'"`]+['"`]\s*,/g
    ];
    
    remoteCodeExecutionPatterns.forEach(pattern => {
      let match;
      while ((match = pattern.exec(code)) !== null) {
        vulnerabilities.push({
          toolName,
          type: VulnerabilityType.REMOTE_CODE_EXECUTION,
          description: 'Potential remote code execution vulnerability',
          details: {
            matchedText: match[0],
            line: code.substring(0, match.index).split('\n').length
          },
          severity: Severity.CRITICAL,
          remediation: 'Avoid constructing and executing code dynamically'
        });
      }
    });
  }
  
  private getLineNumber(node: ts.Node): number {
    const sourceFile = node.getSourceFile();
    const { line } = ts.getLineAndCharacterOfPosition(sourceFile, node.getStart());
    return line + 1;
  }
}
2.5 권한 분석기 (permissionAnalyzer.ts)
typescriptimport { Tool } from '@anthropic-ai/mcp-sdk';
import { ToolVulnerability, Severity, VulnerabilityType } from '../models/scanResult';

export class PermissionAnalyzer {
  private allowedPermissions: string[];
  
  constructor(allowedPermissions: string[] = []) {
    this.allowedPermissions = allowedPermissions;
  }
  
  async analyze(tool: Tool): Promise<ToolVulnerability[]> {
    const vulnerabilities: ToolVulnerability[] = [];
    
    // MCP 도구의 parameters에서 잠재적인 권한 관련 이슈 탐색
    if (tool.parameters) {
      // 민감한 매개변수 이름 찾기
      const sensitiveParamNames = [
        'token', 'key', 'password', 'secret', 'credential', 'auth', 
        'api_key', 'access_token', 'path', 'file', 'filepath'
      ];
      
      for (const param of Object.keys(tool.parameters)) {
        const paramLower = param.toLowerCase();
        
        for (const sensitiveName of sensitiveParamNames) {
          if (paramLower.includes(sensitiveName)) {
            // 매개변수 타입 검사
            const paramDef = tool.parameters[param];
            const isSecureType = this.isSecureParameterType(paramDef);
            
            if (!isSecureType) {
              vulnerabilities.push({
                toolName: tool.name,
                type: VulnerabilityType.SENSITIVE_PARAMETER,
                description: `Tool accepts sensitive parameter "${param}" which may expose credentials`,
                details: {
                  parameterName: param,
                  parameterType: paramDef.type || 'unknown',
                  sensitiveKeyword: sensitiveName
                },
                severity: Severity.HIGH,
                remediation: 'Consider using environment variables or secure credential storage instead of passing sensitive data as parameters'
              });
            }
          }
        }
      }
    }
    
    // 도구 이름에서 잠재적인 권한 관련 이슈 탐색
    const highPrivilegeActions = [
      'delete', 'remove', 'drop', 'exec', 'execute', 'run', 
      'modify', 'update', 'write', 'create', 'admin', 'manage'
    ];
    
    const sensitiveResources = [
      'file', 'system', 'database', 'user', 'account', 'password',
      'credential', 'token', 'key', 'secret', 'config', 'setting'
    ];
    
    const toolNameLower = tool.name.toLowerCase();
    
    for (const action of highPrivilegeActions) {
      for (const resource of sensitiveResources) {
        if (toolNameLower.includes(action) && toolNameLower.includes(resource)) {
          vulnerabilities.push({
            toolName: tool.name,
            type: VulnerabilityType.HIGH_PRIVILEGE_NAME,
            description: `Tool name implies high-privilege operation on sensitive resources`,
            details: {
              action,
              resource,
              fullName: tool.name
            },
            severity: Severity.MEDIUM,
            remediation: 'Review tool privileges and consider limiting its capabilities or adding additional security checks'
          });
          break;
        }
      }
    }
    
    return vulnerabilities;
  }
  
  private isSecureParameterType(paramDef: any): boolean {
    // 안전한 타입 (암호화된 문자열이나 소스에서 직접 제공되지 않는 타입)을 확인
    if (paramDef.format === 'password' || 
        paramDef.format === 'secure-string' ||
        paramDef.secret === true) {
      return true;
    }
    
    // 타입이 string이면서 제한된 열거형 값만 허용하는 경우
    if (paramDef.type === 'string' && Array.isArray(paramDef.enum) && paramDef.enum.length > 0) {
      return true;
    }
    
    return false;
  }
}
2.6 이름 분석기 (nameAnalyzer.ts)
typescriptimport { Tool } from '@anthropic-ai/mcp-sdk';
import { NameConflict } from '../models/scanResult';


---

이름 분석기와 나머지 코드를 계속 구현하겠습니다.

#### 2.6 이름 분석기 (`nameAnalyzer.ts`) - 계속

```typescript
import { Tool } from '@anthropic-ai/mcp-sdk';
import { NameConflict } from '../models/scanResult';

export class NameAnalyzer {
  async analyzeNames(tools: Tool[]): Promise<NameConflict[]> {
    const conflicts: NameConflict[] = [];
    
    // 1. 정확한 이름 충돌 검사
    const nameMap = new Map<string, Tool[]>();
    
    tools.forEach(tool => {
      const name = tool.name.toLowerCase();
      if (!nameMap.has(name)) {
        nameMap.set(name, []);
      }
      nameMap.get(name)?.push(tool);
    });
    
    for (const [name, toolsWithName] of nameMap.entries()) {
      if (toolsWithName.length > 1) {
        conflicts.push({
          type: 'EXACT_MATCH',
          names: toolsWithName.map(t => t.name),
          description: `Multiple tools with identical name (case-insensitive): ${name}`
        });
      }
    }
    
    // 2. 유사한 이름 충돌 검사 (레벤슈타인 거리 사용)
    for (let i = 0; i < tools.length; i++) {
      for (let j = i + 1; j < tools.length; j++) {
        const name1 = tools[i].name.toLowerCase();
        const name2 = tools[j].name.toLowerCase();
        
        // 이미 정확히 일치하는 경우는 건너뜀
        if (name1 === name2) continue;
        
        // 레벤슈타인 거리 계산
        const distance = this.levenshteinDistance(name1, name2);
        const maxLength = Math.max(name1.length, name2.length);
        const similarity = 1 - distance / maxLength;
        
        // 유사도가 높은 경우 (80% 이상)
        if (similarity >= 0.8) {
          conflicts.push({
            type: 'SIMILAR_NAME',
            names: [tools[i].name, tools[j].name],
            description: `Tools with similar names (${Math.round(similarity * 100)}% similarity)`,
            details: {
              similarity: similarity
            }
          });
        }
      }
    }
    
    // 3. 접두사/접미사 충돌 검사
    // 예: get_file과 get_file_content와 같이 하나가 다른 하나의 접두사인 경우
    for (let i = 0; i < tools.length; i++) {
      for (let j = 0; j < tools.length; j++) {
        if (i === j) continue;
        
        const name1 = tools[i].name.toLowerCase();
        const name2 = tools[j].name.toLowerCase();
        
        if (name1.startsWith(name2 + '_') || name2.startsWith(name1 + '_') ||
            name1.endsWith('_' + name2) || name2.endsWith('_' + name1)) {
          conflicts.push({
            type: 'PREFIX_SUFFIX',
            names: [tools[i].name, tools[j].name],
            description: `One tool name is a prefix/suffix of another tool name`
          });
        }
      }
    }
    
    // 4. 하이픈/언더스코어 차이만 있는 이름 충돌 검사
    const normalizedNameMap = new Map<string, Tool[]>();
    
    tools.forEach(tool => {
      // 하이픈과 언더스코어를 제거한 정규화된 이름
      const normalizedName = tool.name.toLowerCase().replace(/[-_]/g, '');
      if (!normalizedNameMap.has(normalizedName)) {
        normalizedNameMap.set(normalizedName, []);
      }
      normalizedNameMap.get(normalizedName)?.push(tool);
    });
    
    for (const [normalizedName, toolsWithName] of normalizedNameMap.entries()) {
      if (toolsWithName.length > 1) {
        conflicts.push({
          type: 'SEPARATOR_DIFFERENCE',
          names: toolsWithName.map(t => t.name),
          description: `Tools with names that differ only in separators (hyphens/underscores)`
        });
      }
    }
    
    return conflicts;
  }
  
  // 레벤슈타인 거리 계산 함수
  private levenshteinDistance(str1: string, str2: string): number {
    const m = str1.length;
    const n = str2.length;
    
    // 빈 문자열 처리
    if (m === 0) return n;
    if (n === 0) return m;
    
    // 2차원 배열 생성
    const d = Array(m + 1).fill(null).map(() => Array(n + 1).fill(null));
    
    // 초기화
    for (let i = 0; i <= m; i++) {
      d[i][0] = i;
    }
    
    for (let j = 0; j <= n; j++) {
      d[0][j] = j;
    }
    
    // 거리 계산
    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        const cost = str1[i - 1] === str2[j - 1] ? 0 : 1;
        d[i][j] = Math.min(
          d[i - 1][j] + 1,      // 삭제
          d[i][j - 1] + 1,      // 삽입
          d[i - 1][j - 1] + cost  // 대체
        );
      }
    }
    
    return d[m][n];
  }
}
```

#### 2.7 버전 분석기 (`versionAnalyzer.ts`)

```typescript
import { MCPServer, Tool } from '@anthropic-ai/mcp-sdk';
import axios from 'axios';
import { VersionChange } from '../models/scanResult';

export class VersionAnalyzer {
  async analyzeVersionChanges(serverUrl: string, depth: number = 3): Promise<VersionChange[]> {
    const changes: VersionChange[] = [];
    
    try {
      // 서버의 최신 버전 정보 가져오기
      const server = new MCPServer(serverUrl);
      const latestTools = await server.getTools();
      const latestToolMap = new Map<string, Tool>();
      
      latestTools.forEach(tool => {
        latestToolMap.set(tool.name, tool);
      });
      
      // 서버의 이전 버전 정보 가져오기 (서버가 버전 이력을 제공하는 경우)
      // 실제 구현에서는 서버가 이전 버전을 제공하는 API가 있어야 함
      // 여기서는 예시로 가상의 API를 호출하는 것으로 가정
      
      for (let versionBack = 1; versionBack <= depth; versionBack++) {
        try {
          // 이전 버전 도구 정보를 가져오기 위한 가상의 API 호출
          // 실제 구현에서는 서버의 API에 맞게 수정 필요
          const response = await axios.get(`${serverUrl}/tools?version=${-versionBack}`);
          
          if (response.data && response.data.tools) {
            const previousTools = response.data.tools as Tool[];
            const previousToolMap = new Map<string, Tool>();
            
            previousTools.forEach(tool => {
              previousToolMap.set(tool.name, tool);
            });
            
            // 도구 변경 사항 분석
            this.detectChanges(latestToolMap, previousToolMap, changes, versionBack);
          }
        } catch (error) {
          console.warn(`Failed to fetch version history (${versionBack} versions back): ${error.message}`);
          break;
        }
      }
    } catch (error) {
      console.error(`Error analyzing version changes: ${error.message}`);
    }
    
    return changes;
  }
  
  private detectChanges(
    currentTools: Map<string, Tool>, 
    previousTools: Map<string, Tool>,
    changes: VersionChange[],
    versionDifference: number
  ) {
    // 1. 새로 추가된 도구 감지
    for (const [name, tool] of currentTools.entries()) {
      if (!previousTools.has(name)) {
        changes.push({
          type: 'TOOL_ADDED',
          toolName: name,
          versionDifference,
          description: `Tool "${name}" was added recently`
        });
      }
    }
    
    // 2. 제거된 도구 감지
    for (const [name, tool] of previousTools.entries()) {
      if (!currentTools.has(name)) {
        changes.push({
          type: 'TOOL_REMOVED',
          toolName: name,
          versionDifference,
          description: `Tool "${name}" was removed`
        });
      }
    }
    
    // 3. 설명이 변경된 도구 감지
    for (const [name, currentTool] of currentTools.entries()) {
      const previousTool = previousTools.get(name);
      
      if (previousTool && currentTool.description !== previousTool.description) {
        const changeSize = this.calculateChangeSize(
          previousTool.description || '', 
          currentTool.description || ''
        );
        
        changes.push({
          type: 'DESCRIPTION_CHANGED',
          toolName: name,
          versionDifference,
          description: `Tool "${name}" description was changed (${changeSize}% difference)`,
          details: {
            changeSize,
            significantChange: changeSize > 50
          }
        });
      }
    }
    
    // 4. 매개변수가 변경된 도구 감지
    for (const [name, currentTool] of currentTools.entries()) {
      const previousTool = previousTools.get(name);
      
      if (previousTool) {
        const currentParams = Object.keys(currentTool.parameters || {});
        const previousParams = Object.keys(previousTool.parameters || {});
        
        // 새로운 매개변수 추가
        for (const param of currentParams) {
          if (!previousParams.includes(param)) {
            changes.push({
              type: 'PARAMETER_ADDED',
              toolName: name,
              versionDifference,
              description: `Tool "${name}" added new parameter "${param}"`,
              details: {
                parameterName: param,
                parameterInfo: currentTool.parameters?.[param]
              }
            });
          }
        }
        
        // 매개변수 제거
        for (const param of previousParams) {
          if (!currentParams.includes(param)) {
            changes.push({
              type: 'PARAMETER_REMOVED',
              toolName: name,
              versionDifference,
              description: `Tool "${name}" removed parameter "${param}"`,
              details: {
                parameterName: param
              }
            });
          }
        }
      }
    }
  }
  
  // 두 문자열 간의 차이 크기를 백분율로 계산
  private calculateChangeSize(str1: string, str2: string): number {
    const distance = this.levenshteinDistance(str1, str2);
    const maxLength = Math.max(str1.length, str2.length);
    return Math.round((distance / maxLength) * 100);
  }
  
  private levenshteinDistance(str1: string, str2: string): number {
    const matrix = Array(str1.length + 1).fill(null).map(() => Array(str2.length + 1).fill(null));
    
    for (let i = 0; i <= str1.length; i++) {
      matrix[i][0] = i;
    }
    
    for (let j = 0; j <= str2.length; j++) {
      matrix[0][j] = j;
    }
    
    for (let i = 1; i <= str1.length; i++) {
      for (let j = 1; j <= str2.length; j++) {
        const cost = str1[i - 1] === str2[j - 1] ? 0 : 1;
        matrix[i][j] = Math.min(
          matrix[i - 1][j] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j - 1] + cost
        );
      }
    }
    
    return matrix[str1.length][str2.length];
  }
}
```

#### 2.8 모델 정의 (`scanResult.ts`)

```typescript
export enum Severity {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW'
}

export enum VulnerabilityType {
  // 도구 설명 관련 취약점
  SUSPICIOUS_PATTERN = 'SUSPICIOUS_PATTERN',
  HIDDEN_HTML = 'HIDDEN_HTML',
  PERMISSION_WORDS = 'PERMISSION_WORDS',
  LLM_DIRECTION = 'LLM_DIRECTION',
  EXCESSIVE_LENGTH = 'EXCESSIVE_LENGTH',
  
  // 코드 관련 취약점
  DANGEROUS_FUNCTION = 'DANGEROUS_FUNCTION',
  COMMAND_INJECTION = 'COMMAND_INJECTION',
  SQL_INJECTION = 'SQL_INJECTION',
  HARDCODED_SECRET = 'HARDCODED_SECRET',
  PATH_TRAVERSAL = 'PATH_TRAVERSAL',
  REMOTE_CODE_EXECUTION = 'REMOTE_CODE_EXECUTION',
  
  // 권한 관련 취약점
  SENSITIVE_PARAMETER = 'SENSITIVE_PARAMETER',
  HIGH_PRIVILEGE_NAME = 'HIGH_PRIVILEGE_NAME'
}

export interface ToolVulnerability {
  toolName: string;
  type: VulnerabilityType;
  description: string;
  details?: any;
  severity: Severity;
  remediation: string;
}

export interface NameConflict {
  type: 'EXACT_MATCH' | 'SIMILAR_NAME' | 'PREFIX_SUFFIX' | 'SEPARATOR_DIFFERENCE';
  names: string[];
  description: string;
  details?: any;
}

export interface VersionChange {
  type: 'TOOL_ADDED' | 'TOOL_REMOVED' | 'DESCRIPTION_CHANGED' | 'PARAMETER_ADDED' | 'PARAMETER_REMOVED';
  toolName: string;
  versionDifference: number;
  description: string;
  details?: any;
}

export interface ScanResult {
  serverUrl: string;
  scanTime: string;
  scanDuration: number;
  toolCount: number;
  vulnerableToolCount: number;
  
  vulnerabilitySummary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  
  nameConflicts: NameConflict[];
  versionChanges: VersionChange[];
  toolVulnerabilities: Record<string, ToolVulnerability[]>;
  overallRiskLevel: Severity;
}
```

### 3. CLI 인터페이스 (`index.ts`)

실제 사용할 수 있는 명령줄 인터페이스를 구현합니다:

```typescript
#!/usr/bin/env node

import { program } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import fs from 'fs';
import path from 'path';
import { MCPSecurityScanner } from './scanner';
import { Severity } from './models/scanResult';

// 색상 맵핑
const severityColors = {
  [Severity.CRITICAL]: chalk.red.bold,
  [Severity.HIGH]: chalk.red,
  [Severity.MEDIUM]: chalk.yellow,
  [Severity.LOW]: chalk.blue
};

// 주 프로그램 정의
program
  .name('mcp-security-scanner')
  .description('Security scanner for MCP (Model Context Protocol) servers')
  .version('1.0.0');

// 스캔 명령어
program
  .command('scan <serverUrl>')
  .description('Scan an MCP server for security vulnerabilities')
  .option('-o, --output <file>', 'Save results to JSON file')
  .option('-c, --config <file>', 'Use custom configuration file')
  .option('-v, --verbose', 'Enable verbose output')
  .option('--historical', 'Include historical version analysis')
  .option('--depth <number>', 'Version history depth for historical analysis', '3')
  .action(async (serverUrl, options) => {
    const spinner = ora('Scanning MCP server...').start();
    
    try {
      // 스캐너 초기화
      const scanner = new MCPSecurityScanner(options.config);
      
      // 스캔 수행
      const result = await scanner.scanServer(serverUrl, {
        historicalScan: options.historical,
        depth: parseInt(options.depth, 10)
      });
      
      spinner.succeed(`Scan completed in ${result.scanDuration}ms`);
      
      // 결과 요약 출력
      console.log('\n' + chalk.bold('Scan Summary:'));
      console.log(`Server URL: ${result.serverUrl}`);
      console.log(`Scan Time: ${result.scanTime}`);
      console.log(`Tools Scanned: ${result.toolCount}`);
      console.log(`Vulnerable Tools: ${result.vulnerableToolCount}`);
      
      console.log('\n' + chalk.bold('Vulnerabilities:'));
      console.log(`Critical: ${severityColors[Severity.CRITICAL](result.vulnerabilitySummary.critical)}`);
      console.log(`High: ${severityColors[Severity.HIGH](result.vulnerabilitySummary.high)}`);
      console.log(`Medium: ${severityColors[Severity.MEDIUM](result.vulnerabilitySummary.medium)}`);
      console.log(`Low: ${severityColors[Severity.LOW](result.vulnerabilitySummary.low)}`);
      console.log(`Total: ${chalk.bold(result.vulnerabilitySummary.total)}`);
      
      console.log('\n' + chalk.bold('Overall Risk Level:'));
      console.log(severityColors[result.overallRiskLevel](result.overallRiskLevel));
      
      // 취약점 상세 정보 출력 (verbose 모드에서만)
      if (options.verbose) {
        console.log('\n' + chalk.bold('Vulnerability Details:'));
        
        Object.entries(result.toolVulnerabilities).forEach(([toolName, vulnerabilities]) => {
          console.log('\n' + chalk.bold(`Tool: ${toolName}`));
          
          vulnerabilities.forEach(vuln => {
            console.log(`  [${severityColors[vuln.severity](vuln.severity)}] ${vuln.type}: ${vuln.description}`);
            if (vuln.remediation) {
              console.log(`    ${chalk.green('Remediation:')} ${vuln.remediation}`);
            }
          });
        });
        
        if (result.nameConflicts.length > 0) {
          console.log('\n' + chalk.bold('Name Conflicts:'));
          
          result.nameConflicts.forEach(conflict => {
            console.log(`  ${conflict.type}: ${conflict.description}`);
            console.log(`    Conflicting Names: ${conflict.names.join(', ')}`);
          });
        }
        
        if (result.versionChanges.length > 0) {
          console.log('\n' + chalk.bold('Recent Version Changes:'));
          
          result.versionChanges.forEach(change => {
            console.log(`  ${change.type} (${change.versionDifference} versions ago): ${change.description}`);
          });
        }
      }
      
      // 결과 파일로 저장 (옵션인 경우)
      if (options.output) {
        const outputPath = path.resolve(options.output);
        fs.writeFileSync(outputPath, JSON.stringify(result, null, 2));
        console.log(chalk.green(`\nResults saved to ${outputPath}`));
      }
      
    } catch (error) {
      spinner.fail(`Scan failed: ${error.message}`);
      if (options.verbose) {
        console.error(error);
      }
      process.exit(1);
    }
  });

// 단일 도구 분석 명령어
program
  .command('analyze-tool <toolFile>')
  .description('Analyze a single MCP tool definition file')
  .option('-o, --output <file>', 'Save results to JSON file')
  .action(async (toolFile, options) => {
    const spinner = ora('Analyzing tool...').start();
    
    try {
      const scanner = new MCPSecurityScanner();
      const toolContent = fs.readFileSync(path.resolve(toolFile), 'utf-8');
      const tool = JSON.parse(toolContent);
      
      const vulnerabilities = await scanner.scanTool(tool);
      
      spinner.succeed('Analysis completed');
      
      console.log('\n' + chalk.bold(`Tool: ${tool.name}`));
      
      if (vulnerabilities.length === 0) {
        console.log(chalk.green('No vulnerabilities detected'));
      } else {
        console.log(`Found ${vulnerabilities.length} vulnerabilities:`);
        
        vulnerabilities.forEach(vuln => {
          console.log(`  [${severityColors[vuln.severity](vuln.severity)}] ${vuln.type}: ${vuln.description}`);
          if (vuln.remediation) {
            console.log(`    ${chalk.green('Remediation:')} ${vuln.remediation}`);
          }
        });
      }
      
      if (options.output) {
        const outputPath = path.resolve(options.output);
        fs.writeFileSync(outputPath, JSON.stringify(vulnerabilities, null, 2));
        console.log(chalk.green(`\nResults saved to ${outputPath}`));
      }
      
    } catch (error) {
      spinner.fail(`Analysis failed: ${error.message}`);
      process.exit(1);
    }
  });

// 도구 생성 검증 명령어
program
  .command('validate <toolDefFile>')
  .description('Validate a tool definition file before publishing')
  .action(async (toolDefFile) => {
    const spinner = ora('Validating tool definition...').start();
    
    try {
      const scanner = new MCPSecurityScanner();
      const toolContent = fs.readFileSync(path.resolve(toolDefFile), 'utf-8');
      const tool = JSON.parse(toolContent);
      
      const vulnerabilities = await scanner.scanTool(tool);
      
      if (vulnerabilities.length === 0) {
        spinner.succeed(chalk.green('Validation passed! Tool definition appears secure'));
      } else {
        spinner.warn(`Found ${vulnerabilities.length} security concerns:`);
        
        const criticalCount = vulnerabilities.filter(v => v.severity === Severity.CRITICAL).length;
        const highCount = vulnerabilities.filter(v => v.severity === Severity.HIGH).length;
        
        vulnerabilities.forEach(vuln => {
          console.log(`  [${severityColors[vuln.severity](vuln.severity)}] ${vuln.type}: ${vuln.description}`);
          if (vuln.remediation) {
            console.log(`    ${chalk.green('Remediation:')} ${vuln.remediation}`);
          }
        });
        
        if (criticalCount > 0 || highCount > 0) {
          console.log(chalk.red('\nValidation failed! Critical or high severity issues must be resolved before publishing.'));
          process.exit(1);
        } else {
          console.log(chalk.yellow('\nValidation completed with warnings. Consider addressing these issues.'));
        }
      }
      
    } catch (error) {
      spinner.fail(`Validation failed: ${error.message}`);
      process.exit(1);
    }
  });

// 프로그램 실행
program.parse(process.argv);
```

### 4. 설정 파일 예시 (`suspiciousPatterns.json`)

```json
{
  "suspiciousPatterns": [
    "file://",
    "~/.ssh",
    "~/.config",
    "~/.cursor",
    "password",
    "token",
    "secret",
    "key",
    "credential",
    "<important>",
    "<instructions>",
    "do not tell",
    "do not mention",
    "before using this tool",
    "http://",
    "https://",
    "exec(",
    "eval(",
    "Function(",
    "setTimeout(",
    "setInterval(",
    "fetch(",
    "axios(",
    "request(",
    "send"
  ],
  "allowedPermissions": [
    "read_only",
    "search",
    "view",
    "list"
  ],
  "disallowedPermissions": [
    "admin",
    "delete",
    "write",
    "modify",
    "execute"
  ],
  "vulnerabilityRules": {
    "maxDescriptionLength": 1000,
    "maxParameterCount": 10,
    "sensitiveParameterNames": [
      "token",
      "password",
      "secret",
      "key",
      "credential",
      "auth",
      "api_key",
      "access_token"
    ]
  }
}
```

### 5. 패키지 구성 (`package.json`)

```json
{
  "name": "mcp-security-scanner",
  "version": "1.0.0",
  "description": "Security scanner for Model Context Protocol (MCP) servers and tools",
  "main": "dist/index.js",
  "bin": {
    "mcp-security-scanner": "./dist/index.js"
  },
  "scripts": {
    "build": "tsc",
    "start": "node dist/index.js",
    "dev": "ts-node src/index.ts",
    "test": "jest",
    "lint": "eslint src/**/*.ts"
  },
  "keywords": [
    "mcp",
    "security",
    "scanner",
    "model-context-protocol",
    "ai",
    "llm"
  ],
  "author": "Your Name",
  "license": "MIT",
  "dependencies": {
    "@anthropic-ai/mcp-sdk": "^1.0.0",
    "axios": "^1.6.0",
    "chalk": "^4.1.2",
    "commander": "^11.1.0",
    "ora": "^5.4.1",
    "typescript": "^5.2.2"
  },
  "devDependencies": {
    "@types/jest": "^29.5.6",
    "@types/node": "^20.8.7",
    "@typescript-eslint/eslint-plugin": "^6.8.0",
    "@typescript-eslint/parser": "^6.8.0",
    "eslint": "^8.51.0",
    "jest": "^29.7.0",
    "ts-jest": "^29.1.1",
    "ts-node": "^10.9.1"
  }
}
```

### 6. 사용 예시

이 도구를 다음과 같이 사용할 수 있습니다:

```bash
# MCP 서버 스캔
npx mcp-security-scanner scan http://localhost:8000

# 상세 결과 표시
npx mcp-security-scanner scan http://localhost:8000 --verbose

# 결과를 파일로 저장
npx mcp-security-scanner scan http://localhost:8000 --output results.json

# 단일 도구 분석
npx mcp-security-scanner analyze-tool path/to/tool.json

# 도구 정의 검증
npx mcp-security-scanner validate path/to/tool-definition.json
```

### 7. 추가적인 보안 검사 기능 제안

위 구현에 더해 다음과 같은 기능들을 향후 추가할 수 있습니다:

1. **ML 기반 이상 탐지**: 자연어 처리 모델을 사용하여 악의적인 지시나 숨겨진 의도를 탐지

2. **API 동작 시뮬레이션**: 실제 도구 호출 없이 동작을 시뮬레이션하여 위험한 결과 예측

3. **지속적 모니터링 시스템**: 정기적으로 자동 스캔을 수행하고 변경사항 추적

4. **권한 상승 탐지**: 도구 간의 조합을 분석하여 권한 상승 가능성 탐지

5. **보안 정책 적용**: 조직 정책에 따라 도구 사용을 제한하는 기능

6. **도구 평판 시스템**: 커뮤니티 기반 평판 시스템을 통해 신뢰할 수 있는 도구 식별

이 코드는 실제 작동하는 MCP 보안 검사 도구의 기본 골격을 제공합니다. 실제 사용을 위해서는 SDK의 정확한 인터페이스와 MCP 서버의 동작 방식에 맞게 일부 조정이 필요할 수 있습니다. 또한, 보안 규칙과 패턴은 새로운 위협이 발견됨에 따라 지속적으로 업데이트되어야 합니다.

이 구현을 통해 MCP 서버와 도구의 보안 취약점을 효과적으로 탐지하고, 안전한 MCP 생태계 구축에 기여할 수 있을 것입니다.