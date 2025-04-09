import { BaseAnalyzer } from './baseAnalyzer';
import { CodeAnalyzer } from './codeAnalyzer';
import { VersionAnalyzer } from './versionAnalyzer';
import { NameAnalyzer } from './nameAnalyzer';
import { PermissionAnalyzer } from './permissionAnalyzer';
import { DescriptionAnalyzer } from './descriptionAnalyzer';

type AnalyzerConstructor = new () => BaseAnalyzer;

export class AnalyzerFactory {
  private static analyzers = new Map<string, AnalyzerConstructor>([
    ['code', CodeAnalyzer as unknown as AnalyzerConstructor],
    ['version', VersionAnalyzer as unknown as AnalyzerConstructor],
    ['name', NameAnalyzer as unknown as AnalyzerConstructor],
    ['permission', PermissionAnalyzer as unknown as AnalyzerConstructor],
    ['description', DescriptionAnalyzer as unknown as AnalyzerConstructor]
  ]);

  /**
   * 모든 분석기 인스턴스를 생성하여 반환합니다.
   * @returns 생성된 분석기 인스턴스 배열
   */
  static createAllAnalyzers(): BaseAnalyzer[] {
    return Array.from(this.analyzers.values()).map(analyzer => new analyzer());
  }

  /**
   * 특정 타입의 분석기 인스턴스를 생성하여 반환합니다.
   * @param type 분석기 타입
   * @returns 생성된 분석기 인스턴스 또는 undefined
   */
  static createAnalyzer(type: string): BaseAnalyzer | undefined {
    const analyzerClass = this.analyzers.get(type.toLowerCase());
    return analyzerClass ? new analyzerClass() : undefined;
  }

  /**
   * 새로운 분석기를 등록합니다.
   * @param type 분석기 타입
   * @param analyzer 분석기 클래스
   */
  static registerAnalyzer(type: string, analyzer: AnalyzerConstructor): void {
    this.analyzers.set(type.toLowerCase(), analyzer);
  }
}