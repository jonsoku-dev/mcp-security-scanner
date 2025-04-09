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
  HIGH_PRIVILEGE_NAME = 'HIGH_PRIVILEGE_NAME',
  
  // 설정 관련 취약점
  INVALID_CONFIG = 'INVALID_CONFIG',
  MISSING_DEPENDENCY = 'MISSING_DEPENDENCY',
  EXECUTION_ERROR = 'EXECUTION_ERROR'
}

export interface VulnerabilityDetails {
  conflictingName?: string;
  [key: string]: any;
}

export interface ToolVulnerability {
  toolName: string;
  type: VulnerabilityType;
  description: string;
  details?: VulnerabilityDetails;
  severity: Severity;
  remediation?: string;
}

export interface NameConflict {
  tool1: string;
  tool2: string;
  recommendation?: string;
}

export interface ScanResult {
  vulnerabilities: ToolVulnerability[];
  nameConflicts: NameConflict[];
  scannedTools: number;
}
