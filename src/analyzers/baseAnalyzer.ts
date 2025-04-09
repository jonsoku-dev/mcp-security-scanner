import { ToolInfo } from '../models/toolInfo';
import { ToolVulnerability } from '../models/scanResult';

export interface BaseAnalyzer {
  /**
   * 도구의 취약점을 분석합니다.
   * @param tool 분석할 도구 정보
   * @returns 발견된 취약점 목록
   */
  analyze(tool: ToolInfo): ToolVulnerability[];
} 