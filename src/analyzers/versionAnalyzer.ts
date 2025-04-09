import { ToolInfo } from '../models/toolInfo';
import { ToolVulnerability, Severity, VulnerabilityType } from '../models/scanResult';
import * as semver from 'semver';
import { BaseAnalyzer } from './baseAnalyzer';

export class VersionAnalyzer implements BaseAnalyzer {
  private minVersions: Map<string, string>;
  private deprecatedVersions: Map<string, string[]>;

  constructor() {
    // 최소 버전 요구사항 설정
    this.minVersions = new Map([
      ['node', '14.0.0'],
      ['npm', '6.0.0'],
      ['typescript', '4.0.0']
    ]);

    // 취약한 버전 목록
    this.deprecatedVersions = new Map([
      ['node', ['8.x', '10.x', '12.x']],
      ['npm', ['4.x', '5.x']],
      ['typescript', ['3.x']]
    ]);
  }

  analyze(tool: ToolInfo): ToolVulnerability[] {
    const issues: ToolVulnerability[] = [];

    if (!tool.version) {
      issues.push({
        toolName: tool.name,
        type: VulnerabilityType.SUSPICIOUS_PATTERN,
        description: 'Tool version is not specified',
        severity: Severity.MEDIUM,
        remediation: 'Specify tool version to ensure compatibility and security'
      });
      return issues;
    }

    // 버전 형식 검증
    if (!this.isValidVersion(tool.version)) {
      issues.push({
        toolName: tool.name,
        type: VulnerabilityType.SUSPICIOUS_PATTERN,
        description: `Invalid version format: ${tool.version}`,
        severity: Severity.LOW,
        remediation: 'Use semantic versioning format (e.g., 1.0.0)'
      });
      return issues;
    }

    // 최소 버전 요구사항 검사
    const minVersion = this.minVersions.get(tool.name.toLowerCase());
    if (minVersion && !this.meetsMinVersion(tool.version, minVersion)) {
      issues.push({
        toolName: tool.name,
        type: VulnerabilityType.SUSPICIOUS_PATTERN,
        description: `Tool version ${tool.version} is below minimum required version ${minVersion}`,
        severity: Severity.HIGH,
        remediation: `Upgrade to version ${minVersion} or higher`
      });
    }

    // 취약한 버전 검사
    const deprecatedList = this.deprecatedVersions.get(tool.name.toLowerCase());
    if (deprecatedList && this.isDeprecatedVersion(tool.version, deprecatedList)) {
      issues.push({
        toolName: tool.name,
        type: VulnerabilityType.SUSPICIOUS_PATTERN,
        description: `Tool version ${tool.version} is deprecated or known to have vulnerabilities`,
        severity: Severity.HIGH,
        remediation: 'Upgrade to a supported version'
      });
    }

    // 와일드카드 버전 검사
    if (this.hasWildcard(tool.version)) {
      issues.push({
        toolName: tool.name,
        type: VulnerabilityType.SUSPICIOUS_PATTERN,
        description: 'Version contains wildcards which may lead to unexpected updates',
        severity: Severity.MEDIUM,
        remediation: 'Specify exact version number'
      });
    }

    return issues;
  }

  private isValidVersion(version: string): boolean {
    return semver.valid(version) !== null || /^\d+\.\d+\.\d+/.test(version);
  }

  private meetsMinVersion(version: string, minVersion: string): boolean {
    return semver.gte(version, minVersion);
  }

  private isDeprecatedVersion(version: string, deprecatedList: string[]): boolean {
    return deprecatedList.some(deprecated => {
      if (deprecated.endsWith('.x')) {
        const major = deprecated.split('.')[0];
        return version.startsWith(major + '.');
      }
      return version === deprecated;
    });
  }

  private hasWildcard(version: string): boolean {
    return version.includes('*') || version.includes('x') || version.includes('^') || version.includes('~');
  }
}
