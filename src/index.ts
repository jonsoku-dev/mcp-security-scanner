import { MCPSecurityScanner } from './scanner';
import { ScanResult, ToolVulnerability, Severity, VulnerabilityType } from './models/scanResult';
import chalk from 'chalk';
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { 
  CallToolRequestSchema, 
  type CallToolRequest,
  ReadResourceRequestSchema,
  type ReadResourceRequest,
  GetPromptRequestSchema,
  type GetPromptRequest
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { execSync } from 'child_process';
import path from 'path';
import os from 'os';

export interface ScanOptions {
  verbose?: boolean;
  configPath?: string;
}

// MCP 서버 인스턴스 생성
const server = new Server(
  {
    name: "mcp-security-scanner",
    version: "1.0.0"
  },
  {
    capabilities: {
      tools: {}
    }
  }
);

// MCP 설정 파일 경로
const MCP_CONFIG_PATH = path.join(os.homedir(), '.cursor', 'mcp.json');

// MCP 설정 파일 읽기
function getMCPConfig() {
  try {
    const configContent = require(MCP_CONFIG_PATH);
    return configContent.mcpServers || {};
  } catch (error) {
    console.error(chalk.red('MCP 설정 파일을 읽을 수 없습니다:', MCP_CONFIG_PATH));
    return {};
  }
}

// MCP 도구 실행 테스트
async function testMCPTool(name: string, config: any): Promise<ToolVulnerability[]> {
  const vulnerabilities: ToolVulnerability[] = [];
  
  try {
    let command: string;
    if (config.url) {
      // URL 기반 도구는 건너뜀
      return [];
    } else if (config.command && config.args) {
      command = `${config.command} ${config.args.join(' ')}`;
    } else if (config.command) {
      command = config.command;
    } else {
      vulnerabilities.push({
        toolName: name,
        type: VulnerabilityType.INVALID_CONFIG,
        description: '도구 실행 명령이 올바르게 설정되지 않았습니다.',
        severity: Severity.HIGH,
        remediation: 'command 또는 url 설정을 확인해주세요.'
      });
      return vulnerabilities;
    }

    // 도구 실행 테스트
    try {
      execSync(`${command} --help`, { stdio: 'ignore' });
    } catch (error) {
      vulnerabilities.push({
        toolName: name,
        type: VulnerabilityType.EXECUTION_ERROR,
        description: '도구 실행에 실패했습니다.',
        severity: Severity.HIGH,
        remediation: '도구가 올바르게 설치되어 있는지 확인해주세요.'
      });
    }

    // 환경 변수 검사
    if (config.env) {
      const missingEnvVars = Object.keys(config.env).filter(key => !process.env[key] && !config.env[key]);
      if (missingEnvVars.length > 0) {
        vulnerabilities.push({
          toolName: name,
          type: VulnerabilityType.MISSING_DEPENDENCY,
          description: `필요한 환경 변수가 설정되지 않았습니다: ${missingEnvVars.join(', ')}`,
          severity: Severity.MEDIUM,
          remediation: '누락된 환경 변수를 설정해주세요.'
        });
      }
    }

  } catch (error) {
    vulnerabilities.push({
      toolName: name,
      type: VulnerabilityType.EXECUTION_ERROR,
      description: `도구 검사 중 오류 발생: ${error instanceof Error ? error.message : '알 수 없는 오류'}`,
      severity: Severity.HIGH,
      remediation: '도구 설정을 확인해주세요.'
    });
  }

  return vulnerabilities;
}

// 스캔 요청 핸들러 등록
server.setRequestHandler(CallToolRequestSchema, async (request: CallToolRequest) => {
  if (request.params.name !== 'scan') {
    throw new Error('Unknown tool');
  }

  const args = request.params.arguments as { verbose?: boolean; configPath?: string; shouldScan?: boolean };
  
  if (!args.shouldScan) {
    return {
      content: [{
        type: "text",
        text: "검사를 시작하려면 shouldScan: true를 설정해주세요."
      }]
    };
  }

  try {
    console.log(chalk.blue('🔍 MCP 도구 보안 검사를 시작합니다...'));
    
    const mcpConfig = getMCPConfig();
    const allVulnerabilities: ToolVulnerability[] = [];
    const nameConflicts: { tool1: string; tool2: string; recommendation?: string }[] = [];
    
    // 모든 도구 검사
    for (const [name, config] of Object.entries(mcpConfig)) {
      console.log(chalk.blue(`\n검사 중: ${name}`));
      const vulns = await testMCPTool(name, config);
      allVulnerabilities.push(...vulns);
    }

    // 이름 충돌 검사
    const toolNames = Object.keys(mcpConfig);
    for (let i = 0; i < toolNames.length; i++) {
      for (let j = i + 1; j < toolNames.length; j++) {
        const name1 = toolNames[i].toLowerCase();
        const name2 = toolNames[j].toLowerCase();
        if (name1.includes(name2) || name2.includes(name1)) {
          nameConflicts.push({
            tool1: toolNames[i],
            tool2: toolNames[j],
            recommendation: '도구 이름이 서로 포함 관계에 있습니다. 더 명확한 이름을 사용하세요.'
          });
        }
      }
    }

    const result: ScanResult = {
      scannedTools: Object.keys(mcpConfig).length,
      vulnerabilities: allVulnerabilities,
      nameConflicts
    };

    if (args.verbose) {
      console.log(chalk.gray('\n상세 정보:'));
      console.log(chalk.gray('  • 검사한 도구:', result.scannedTools));
      console.log(chalk.gray('  • 발견된 취약점:', result.vulnerabilities.length));
      console.log(chalk.gray('  • 이름 충돌:', result.nameConflicts.length));
    }

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
});

// 설정 리소스 핸들러 등록
server.setRequestHandler(ReadResourceRequestSchema, async (request: ReadResourceRequest) => {
  const uri = new URL(request.params.uri);
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
      uri: request.params.uri,
      text: content
    }]
  };
});

// 스캔 결과 프롬프트 핸들러 등록
server.setRequestHandler(GetPromptRequestSchema, async (request: GetPromptRequest) => {
  if (request.params.name !== "scan-result") {
    throw new Error("Unknown prompt");
  }

  const args = request.params.arguments as { result: string };
  const scanResult = JSON.parse(args.result) as ScanResult;
  
  return {
    description: "보안 스캔 결과를 분석하는 프롬프트",
    messages: [{
      role: "user",
      content: {
        type: "text",
        text: `보안 스캔 결과를 분석해주세요:\n${JSON.stringify(scanResult, null, 2)}`
      }
    }]
  };
});

// 서버 시작 함수
export async function startServer() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.log(chalk.green('MCP 보안 스캐너 서버가 시작되었습니다.'));
}

export async function scan(options: ScanOptions & { shouldScan?: boolean }): Promise<ScanResult> {
  try {
    if (!options.shouldScan) {
      throw new Error("검사를 시작하려면 shouldScan: true를 설정해주세요.");
    }

    console.log(chalk.blue('🔍 MCP 보안 검사를 시작합니다...'));
    
    const scanner = new MCPSecurityScanner({
      configPath: options.configPath
    });
    
    const mcpConfig = getMCPConfig();
    const allVulnerabilities: ToolVulnerability[] = [];
    const nameConflicts: { tool1: string; tool2: string; recommendation?: string }[] = [];
    
    // 모든 도구 검사
    for (const [name, config] of Object.entries(mcpConfig)) {
      console.log(chalk.blue(`\n검사 중: ${name}`));
      const vulns = await testMCPTool(name, config);
      allVulnerabilities.push(...vulns);
    }

    // 이름 충돌 검사
    const toolNames = Object.keys(mcpConfig);
    for (let i = 0; i < toolNames.length; i++) {
      for (let j = i + 1; j < toolNames.length; j++) {
        const name1 = toolNames[i].toLowerCase();
        const name2 = toolNames[j].toLowerCase();
        if (name1.includes(name2) || name2.includes(name1)) {
          nameConflicts.push({
            tool1: toolNames[i],
            tool2: toolNames[j],
            recommendation: '도구 이름이 서로 포함 관계에 있습니다. 더 명확한 이름을 사용하세요.'
          });
        }
      }
    }

    const result: ScanResult = {
      scannedTools: Object.keys(mcpConfig).length,
      vulnerabilities: allVulnerabilities,
      nameConflicts
    };

    if (options.verbose) {
      console.log(chalk.gray('\n상세 정보:'));
      console.log(chalk.gray('  • 검사한 도구:', result.scannedTools));
      console.log(chalk.gray('  • 발견된 취약점:', result.vulnerabilities.length));
      console.log(chalk.gray('  • 이름 충돌:', result.nameConflicts.length));
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
