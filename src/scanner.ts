import { AnalyzerFactory } from './analyzers/analyzerFactory';
import { ConfigLoader } from './utils/configLoader';
import { Logger } from './utils/logger';
import { ToolInfo, ToolParameter } from './models/toolInfo';
import { ScanResult, ToolVulnerability, VulnerabilityType } from './models/scanResult';
import { BaseAnalyzer } from './analyzers/baseAnalyzer';
import * as fs from 'fs/promises';
import * as path from 'path';

export interface ScannerOptions {
  configPath?: string;
  ignorePatterns?: string[];
  logLevel?: string;
}

export class MCPSecurityScanner {
  private analyzers: BaseAnalyzer[];
  private logger: Logger;
  private ignorePatterns: string[];

  constructor(options: ScannerOptions = {}) {
    const config = new ConfigLoader().loadConfig(options.configPath);
    this.logger = new Logger(options.logLevel || config.logLevel || 'info');
    this.ignorePatterns = options.ignorePatterns || [];
    
    // 팩토리를 통해 모든 분석기 생성
    this.analyzers = AnalyzerFactory.createAllAnalyzers();
    
    // 설정이 필요한 분석기들 초기화
    const descriptionAnalyzer = AnalyzerFactory.createAnalyzer('description');
    if (descriptionAnalyzer) {
      Object.assign(descriptionAnalyzer, { suspiciousPatterns: config.suspiciousPatterns });
    }

    const permissionAnalyzer = AnalyzerFactory.createAnalyzer('permission');
    if (permissionAnalyzer) {
      Object.assign(permissionAnalyzer, { allowedPermissions: config.allowedPermissions });
    }
  }

  async scanDirectory(directory: string): Promise<ScanResult> {
    this.logger.info(`스캔 시작: ${directory}`);
    
    const tools = await this.discoverTools(directory);
    return this.scanTools(tools);
  }

  private async discoverTools(directory: string): Promise<ToolInfo[]> {
    const tools: ToolInfo[] = [];
    
    try {
      const files = await fs.readdir(directory, { recursive: true });
      
      for (const file of files) {
        if (this.ignorePatterns.some(pattern => file.match(pattern))) {
          continue;
        }
        
        if (file.endsWith('package.json')) {
          const content = await fs.readFile(path.join(directory, file), 'utf-8');
          const pkg = JSON.parse(content);
          
          tools.push({
            name: pkg.name || 'unknown',
            description: pkg.description || '',
            version: pkg.version,
            parameters: this.extractParameters(pkg),
            permissions: pkg.permissions || [],
            dependencies: pkg.dependencies || {}
          });
        }
      }
    } catch (error) {
      this.logger.error(`도구 검색 중 오류 발생: ${error}`);
    }
    
    return tools;
  }

  private extractParameters(pkg: any): ToolParameter[] {
    const parameters: ToolParameter[] = [];
    
    if (pkg.mcp && pkg.mcp.parameters) {
      for (const param of pkg.mcp.parameters) {
        parameters.push({
          name: param.name || '',
          type: param.type || 'string',
          description: param.description,
          required: param.required || false
        });
      }
    }
    
    return parameters;
  }

  private async scanTools(tools: ToolInfo[]): Promise<ScanResult> {
    this.logger.info(`${tools.length}개의 도구 검사 시작`);
    
    const vulnerabilities: ToolVulnerability[] = [];
    const nameConflicts: { tool1: string; tool2: string; recommendation?: string }[] = [];
    const scannedTools = tools.length;

    // 각 도구 검사
    for (const tool of tools) {
      // 모든 분석기로 검사 수행
      for (const analyzer of this.analyzers) {
        const analyzerIssues = analyzer.analyze(tool);
        vulnerabilities.push(...analyzerIssues);

        // 이름 충돌 관련 취약점 처리
        const nameConflictIssues = analyzerIssues.filter(issue => issue.type === VulnerabilityType.NAME_CONFLICT);
        for (const issue of nameConflictIssues) {
          if (issue.details?.conflictingName) {
            nameConflicts.push({
              tool1: tool.name,
              tool2: issue.details.conflictingName,
              recommendation: issue.remediation
            });
          }
        }
      }
    }

    return {
      vulnerabilities,
      nameConflicts,
      scannedTools
    };
  }
}
