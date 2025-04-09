import { MCPSecurityScanner } from './scanner';
import { ScanResult, ToolVulnerability, Severity } from './models/scanResult';
import chalk from 'chalk';
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

export interface ScanOptions {
  directory: string;
  verbose?: boolean;
  configPath?: string;
  ignorePatterns?: string[];
}

// MCP 서버 인스턴스 생성
const server = new McpServer({
  name: "mcp-security-scanner",
  version: "1.0.0"
});

// 스캔 도구 등록
server.tool(
  "scan",
  {
    directory: z.string(),
    verbose: z.boolean().optional(),
    configPath: z.string().optional(),
    ignorePatterns: z.array(z.string()).optional()
  },
  async (params: { 
    directory: string; 
    verbose?: boolean; 
    configPath?: string; 
    ignorePatterns?: string[] 
  }) => {
    try {
      const result = await scan(params);
      return {
        content: [{
          type: "text",
          text: JSON.stringify(result, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: "text",
          text: `Error: ${error instanceof Error ? error.message : '알 수 없는 오류'}`
        }],
        isError: true
      };
    }
  }
);

// 설정 리소스 등록
server.resource(
  "config",
  "config://{configType}",
  async (uri: URL) => {
    const configType = uri.pathname.split('/').pop();
    let content = '';
    
    switch (configType) {
      case 'vulnerability-rules':
        content = JSON.stringify(require('./config/vulnerabilityRules.json'), null, 2);
        break;
      case 'allowed-permissions':
        content = JSON.stringify(require('./config/allowedPermissions.json'), null, 2);
        break;
      case 'suspicious-patterns':
        content = JSON.stringify(require('./config/suspiciousPatterns.json'), null, 2);
        break;
      default:
        throw new Error(`Unknown config type: ${configType}`);
    }
    
    return {
      contents: [{
        uri: uri.href,
        text: content
      }]
    };
  }
);

// 스캔 결과 프롬프트 등록
server.prompt(
  "scan-result",
  "보안 스캔 결과를 분석하는 프롬프트",
  {
    result: z.string()
  },
  async (args, extra) => {
    const scanResult = JSON.parse(args.result) as ScanResult;
    return {
      messages: [{
        role: "user",
        content: {
          type: "text",
          text: `보안 스캔 결과를 분석해주세요:\n${JSON.stringify(scanResult, null, 2)}`
        }
      }]
    };
  }
);

// 서버 시작 함수
export async function startServer() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.log(chalk.green('MCP 보안 스캐너 서버가 시작되었습니다.'));
}

export async function scan(options: string | ScanOptions): Promise<ScanResult> {
  const scanOptions = typeof options === 'string' ? { directory: options } : options;
  
  try {
    console.log(chalk.blue('🔍 MCP 보안 검사를 시작합니다...'));
    
    const scanner = new MCPSecurityScanner({
      configPath: scanOptions.configPath,
      ignorePatterns: scanOptions.ignorePatterns
    });
    
    const result = await scanner.scanDirectory(scanOptions.directory);
    
    if (result.vulnerabilities.length === 0 && result.nameConflicts.length === 0) {
      console.log(chalk.green('✓ 모든 도구가 보안 검사를 통과했습니다!'));
    } else {
      if (result.vulnerabilities.length > 0) {
        console.log(chalk.yellow('\n⚠ 취약점이 발견되었습니다:'));
        
        for (const vuln of result.vulnerabilities) {
          console.log(chalk.yellow(`\n도구: ${vuln.toolName}`));
          console.log(chalk.red(`  • ${vuln.description}`));
          console.log(chalk.red(`    심각도: ${Severity[vuln.severity]}`));
          if (vuln.remediation) {
            console.log(chalk.cyan(`    해결 방안: ${vuln.remediation}`));
          }
        }
      }
      
      if (result.nameConflicts.length > 0) {
        console.log(chalk.yellow('\n⚠ 이름 충돌이 발견되었습니다:'));
        for (const conflict of result.nameConflicts) {
          console.log(chalk.red(`  • ${conflict.tool1} ↔ ${conflict.tool2}`));
          if (conflict.recommendation) {
            console.log(chalk.cyan(`    추천: ${conflict.recommendation}`));
          }
        }
      }
      
      // 통계 정보 출력
      const totalTools = result.scannedTools;
      const vulnerableTools = new Set(result.vulnerabilities.map(v => v.toolName)).size;
      const totalIssues = result.vulnerabilities.length;
      
      console.log(chalk.cyan('\n📊 검사 통계:'));
      console.log(chalk.cyan(`  • 검사한 도구: ${totalTools}`));
      console.log(chalk.cyan(`  • 취약한 도구: ${vulnerableTools}`));
      console.log(chalk.cyan(`  • 총 이슈 수: ${totalIssues}`));
      console.log(chalk.cyan(`  • 이름 충돌 수: ${result.nameConflicts.length}`));
      
      if (scanOptions.verbose) {
        console.log(chalk.gray('\n🔍 상세 정보:'));
        console.log(chalk.gray('  • 검사 경로:', scanOptions.directory));
        console.log(chalk.gray('  • 설정 파일:', scanOptions.configPath || '기본 설정'));
        if (scanOptions.ignorePatterns?.length) {
          console.log(chalk.gray('  • 무시된 패턴:', scanOptions.ignorePatterns.join(', ')));
        }
      }
    }
    
    return result;
  } catch (error) {
    console.error(chalk.red('❌ 보안 검사 중 오류가 발생했습니다:'));
    console.error(chalk.red(`  ${error instanceof Error ? error.message : '알 수 없는 오류'}`));
    throw error;
  }
}

// 유틸리티 함수들
export function getSeverityColor(severity: Severity): typeof chalk.red {
  switch (severity) {
    case Severity.HIGH:
      return chalk.red;
    case Severity.MEDIUM:
      return chalk.yellow;
    case Severity.LOW:
      return chalk.blue;
    default:
      return chalk.gray;
  }
}

export function formatVulnerability(vuln: ToolVulnerability): string {
  const severityColor = getSeverityColor(vuln.severity);
  return `${severityColor(Severity[vuln.severity])} - ${vuln.description}`;
}

export { MCPSecurityScanner, Severity, ScanResult, ToolVulnerability };

// 서버 자동 시작 (직접 실행된 경우)
if (require.main === module) {
  startServer().catch(error => {
    console.error('서버 시작 중 오류 발생:', error);
    process.exit(1);
  });
}
