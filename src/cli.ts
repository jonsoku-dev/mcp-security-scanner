#!/usr/bin/env node

import { MCPSecurityScanner } from './scanner';
import { Command } from 'commander';
import chalk from 'chalk';
import { Severity } from './models/scanResult';
import { scan } from './index';

const program = new Command();

interface ScanOptions {
  config?: string;
  verbose?: boolean;
  shouldScan?: boolean;
}

program
  .name('mcp-security-scanner')
  .description('MCP 도구들의 보안 취약점을 검사하는 도구')
  .version('1.0.0');

program
  .command('scan')
  .description('등록된 MCP 도구들의 보안을 검사합니다')
  .option('-c, --config <path>', '설정 파일 경로')
  .option('-v, --verbose', '상세한 로그 출력', false)
  .action(async (options: ScanOptions) => {
    try {
      console.log(chalk.blue('🔍 MCP 도구 보안 검사를 시작합니다...'));
      
      const result = await scan({
        configPath: options.config,
        verbose: options.verbose,
        shouldScan: true
      });

      // 취약점 출력
      if (result.vulnerabilities.length > 0) {
        console.log(chalk.red('\n🚨 발견된 취약점:'));
        result.vulnerabilities.forEach(vuln => {
          console.log(chalk.yellow(`\n도구: ${vuln.toolName}`));
          console.log(`유형: ${getVulnerabilityTypeLabel(vuln.type)}`);
          console.log(`설명: ${vuln.description}`);
          console.log(`심각도: ${getSeverityLabel(vuln.severity)}`);
          if (vuln.remediation) {
            console.log(chalk.green(`해결 방법: ${vuln.remediation}`));
          }
        });
      }

      // 이름 충돌 출력
      if (result.nameConflicts.length > 0) {
        console.log(chalk.red('\n⚠️ 이름 충돌:'));
        result.nameConflicts.forEach(conflict => {
          console.log(`\n${conflict.tool1} <-> ${conflict.tool2}`);
          if (conflict.recommendation) {
            console.log(chalk.green(`추천: ${conflict.recommendation}`));
          }
        });
      }

      // 요약 출력
      console.log(chalk.blue(`\n📊 스캔 완료: ${result.scannedTools}개의 도구 검사됨`));
      console.log(chalk.yellow(`발견된 취약점: ${result.vulnerabilities.length}`));
      console.log(chalk.yellow(`이름 충돌: ${result.nameConflicts.length}`));

      if (result.vulnerabilities.length === 0 && result.nameConflicts.length === 0) {
        console.log(chalk.green('\n✅ 문제가 발견되지 않았습니다!'));
      }

    } catch (error) {
      console.error(chalk.red('❌ 오류 발생:'), error);
      process.exit(1);
    }
  });

function getSeverityLabel(severity: Severity): string {
  switch (severity) {
    case Severity.CRITICAL:
      return chalk.red('치명적');
    case Severity.HIGH:
      return chalk.red('높음');
    case Severity.MEDIUM:
      return chalk.yellow('중간');
    case Severity.LOW:
      return chalk.green('낮음');
    default:
      return chalk.gray('알 수 없음');
  }
}

function getVulnerabilityTypeLabel(type: string): string {
  const labels: { [key: string]: string } = {
    INVALID_CONFIG: '설정 오류',
    EXECUTION_ERROR: '실행 오류',
    MISSING_DEPENDENCY: '의존성 누락',
    NAME_CONFLICT: '이름 충돌',
    SUSPICIOUS_PATTERN: '의심스러운 패턴',
    HIDDEN_HTML: '숨겨진 HTML',
    PERMISSION_WORDS: '권한 관련 단어',
    LLM_DIRECTION: 'LLM 지시',
    EXCESSIVE_LENGTH: '과도한 길이',
    DANGEROUS_FUNCTION: '위험한 함수',
    COMMAND_INJECTION: '명령어 삽입',
    SQL_INJECTION: 'SQL 삽입',
    HARDCODED_SECRET: '하드코딩된 비밀값',
    PATH_TRAVERSAL: '경로 탐색',
    REMOTE_CODE_EXECUTION: '원격 코드 실행',
    SENSITIVE_PARAMETER: '민감한 매개변수',
    HIGH_PRIVILEGE_NAME: '높은 권한 이름'
  };

  return labels[type] || type;
}

program.parse(); 