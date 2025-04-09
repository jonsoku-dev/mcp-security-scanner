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
npm install @modelcontextprotocol/security-scanner
```

## 사용 방법

### 1. 명령줄에서 실행

```bash
npx mcp-security-scanner scan --directory ./my-project --verbose
```

### 2. 프로그래밍 방식으로 사용

```typescript
import { MCPSecurityScanner } from '@modelcontextprotocol/security-scanner';

const scanner = new MCPSecurityScanner({
  configPath: './config.json',
  ignorePatterns: ['*.test.ts']
});

const result = await scanner.scanDirectory('./my-project');
console.log(result);
```

## AI 도구에 등록하기

### Claude Desktop에 등록

1. Claude Desktop 설정 열기
2. 'Tools & Integrations' 섹션으로 이동
3. 'Add Custom Tool' 클릭
4. 다음 정보 입력:
   ```json
   {
     "name": "mcp-security-scanner",
     "description": "MCP 도구들의 보안 취약점을 검사하는 도구",
     "command": "npx mcp-security-scanner",
     "transport": "stdio"
   }
   ```

### Cursor에 등록

1. Cursor 설정 파일 열기 (`~/.cursor/config.json`)
2. `tools` 섹션에 다음 추가:
   ```json
   {
     "tools": {
       "mcp-security-scanner": {
         "command": "npx mcp-security-scanner",
         "transport": "stdio"
       }
     }
   }
   ```

### CLIne에 등록

1. CLIne 설정 디렉토리로 이동
2. `tools.json` 파일에 다음 추가:
   ```json
   {
     "mcp-security-scanner": {
       "command": "npx mcp-security-scanner",
       "transport": "stdio"
     }
   }
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