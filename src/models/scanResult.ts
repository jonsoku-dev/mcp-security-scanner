export enum Severity {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW'
}

export enum VulnerabilityType {
  SUSPICIOUS_PATTERN = 'SUSPICIOUS_PATTERN',
  HIDDEN_HTML = 'HIDDEN_HTML',
  PERMISSION_WORDS = 'PERMISSION_WORDS',
  LLM_DIRECTION = 'LLM_DIRECTION',
  EXCESSIVE_LENGTH = 'EXCESSIVE_LENGTH',
  NAME_CONFLICT = 'NAME_CONFLICT'
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
