#!/usr/bin/env node

import { MCPSecurityScanner } from './scanner';
import { Command } from 'commander';
import chalk from 'chalk';
import { Severity } from './models/scanResult';

const program = new Command();

interface ScanOptions {
  directory: string;
  config?: string;
  ignore?: string[];
  verbose?: boolean;
}

program
  .name('mcp-security-scanner')
  .description('MCP 도구들의 보안 취약점을 검사하는 도구')
  .version('1.0.0');

program
  .command('scan')
  .description('지정된 디렉토리의 MCP 도구들을 스캔합니다')
  .requiredOption('-d, --directory <path>', '스캔할 디렉토리 경로')
  .option('-c, --config <path>', '설정 파일 경로')
  .option('-i, --ignore <patterns...>', '무시할 파일 패턴들')
  .option('-v, --verbose', '상세한 로그 출력', false)
  .action(async (options: ScanOptions) => {
    try {
      const scanner = new MCPSecurityScanner({
        configPath: options.config,
        ignorePatterns: options.ignore,
        logLevel: options.verbose ? 'debug' : 'info'
      });

      console.log(chalk.blue('🔍 보안 스캔 시작...'));
      const result = await scanner.scanDirectory(options.directory);

      // 취약점 출력
      if (result.vulnerabilities.length > 0) {
        console.log(chalk.red('\n🚨 발견된 취약점:'));
        result.vulnerabilities.forEach(vuln => {
          console.log(chalk.yellow(`\n도구: ${vuln.toolName}`));
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
    case Severity.LOW:
      return chalk.green('낮음');
    case Severity.MEDIUM:
      return chalk.yellow('중간');
    case Severity.HIGH:
      return chalk.red('높음');
    default:
      return chalk.gray('알 수 없음');
  }
}

program.parse(); 