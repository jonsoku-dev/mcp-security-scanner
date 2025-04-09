# MCP 보안 스캐너

MCP(Model Context Protocol) 보안 스캐너는 MCP 도구들의 보안 취약점을 검사하는 도구입니다. 버전 관리, 권한 검사, 의심스러운 패턴 탐지 등 다양한 보안 검사를 수행합니다.

## 기능

- 도구 버전 취약점 검사
- 권한 관리 검사
- 의심스러운 패턴 탐지
- 도구 이름 충돌 검사
- 상세한 보안 리포트 생성

## 아키텍처

```mermaid
graph TD
    A[MCP 클라이언트] -->|요청| B[MCP 서버]
    B --> C[보안 스캐너]
    C --> D[버전 분석기]
    C --> E[권한 분석기]
    C --> F[패턴 분석기]
    C --> G[이름 충돌 분석기]
    D --> H[취약점 보고서]
    E --> H
    F --> H
    G --> H
    H --> B
    B -->|응답| A
```

## 설치

```bash
npm install @jonsoku2/mcp-security-scanner
```

## 사용 방법

### 1. 명령줄에서 실행

```bash
npx @jonsoku2/mcp-security-scanner scan --directory ./my-project --verbose
```

### 2. 프로그래밍 방식으로 사용

```typescript
import { MCPSecurityScanner } from '@jonsoku2/mcp-security-scanner';

const scanner = new MCPSecurityScanner({
  configPath: './config.json',
  ignorePatterns: ['*.test.ts']
});

const result = await scanner.scanDirectory('./my-project');
console.log(result);
```

## 의존성

### 주요 의존성
- @modelcontextprotocol/sdk: ^1.0.0
- chalk: ^4.1.2
- commander: ^11.1.0
- semver: ^7.5.4
- zod: ^3.22.4

### 개발 의존성
- TypeScript: ^5.3.3
- Jest: ^29.7.0
- ts-node: ^10.9.2
- rimraf: ^5.0.10

## 스크립트

```bash
# 빌드
npm run build

# 개발 모드 실행
npm run dev

# 패키지 미리보기
npm run pack:preview

# 배포
npm run release:patch  # 패치 버전 배포
npm run release:minor  # 마이너 버전 배포
npm run release:major  # 메이저 버전 배포
```

## 설정

### 취약점 규칙 설정

`vulnerabilityRules.json`:
```json
{
  "minVersions": {
    "node": "14.0.0",
    "npm": "6.0.0"
  },
  "deprecatedVersions": {
    "node": ["<12.0.0"],
    "npm": ["<5.0.0"]
  }
}
```

### 허용된 권한 설정

`allowedPermissions.json`:
```json
{
  "allowedPermissions": [
    "fs.read",
    "net.connect"
  ]
}
```

### 의심스러운 패턴 설정

`suspiciousPatterns.json`:
```json
{
  "patterns": [
    "eval\\(",
    "Function\\(",
    "require\\('child_process'\\)"
  ]
}
```

## 라이선스

MIT

## 기여하기

1. 이 저장소를 포크합니다
2. 새 브랜치를 생성합니다 (`git checkout -b feature/amazing-feature`)
3. 변경사항을 커밋합니다 (`git commit -m 'Add amazing feature'`)
4. 브랜치를 푸시합니다 (`git push origin feature/amazing-feature`)
5. Pull Request를 생성합니다

## 작성자

jonsoku2 