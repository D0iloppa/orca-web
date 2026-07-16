# orca-web — 구현 계획 (plan.md)

> **이 문서는 TASK_CONTEXT.md의 새 결정으로 대체됨** — §3(node-pty)·§4(⚠️ OPEN "orca가 뭘 구동하는지")는 "Orca 데스크톱 relay 프로토콜에 붙는 브라우저 클라이언트"로 확정되어 폐기. 히스토리 보존용으로만 유지.

> 이 문서는 **계획 전용**이다. 이 세션에서는 코드를 작성하지 않았다 — 이 워크스페이스
> (`/mnt/c/DEV/docker/orca-web`)에서 새 세션을 열어 이 문서를 읽고 그대로 이어서
> 구현하면 된다. 확정 안 된 지점은 "⚠️ OPEN"으로 명시했다 — 구현 착수 전에 반드시
> 해소해야 한다.

## 배경 / 목적

"orca 모바일처럼" — WebSocket으로 원격 접속 가능한 웹 단말 페이지를 만든다.
`void-ai-launcher`(별개 저장소)와는 무관하다. `doil-sb`(`/mnt/c/DEV/docker/doil-sb`,
관리자 콘솔을 이미 운용 중인 Node/Express 게이트웨이)에 **서브모듈로 마운트해서
서빙**하는 구조로 최종 확정했다.

## 확정된 아키텍처 결정

### 1. 배치: doil-sb 마운트 서브모듈 (독립 서비스 아님)

- 이 리포(`orca-web`)는 **독립적으로 git 관리**되지만, 런타임에는 doil-sb 프로세스
  **안에서** `require()`돼 실행된다 — 별도 포트/컨테이너/nginx location 불필요.
- doil-sb의 기존 패턴을 그대로 따른다(`app.js` 확인 결과):
  ```js
  // doil-sb/app.js 기존 코드 (확인됨, 464-466행)
  registerGameSocket(io);
  require('./dobisBridge').registerDobis(io);
  ```
  같은 자리에 다음을 추가:
  ```js
  require('./submodules/orca-web').registerOrcaWeb(app, io);
  ```
- **`.gitmodules`에 추가**: `doil-sb/submodules/orca-web` 경로로 이 리포를 서브모듈
  등록(void-ai-launcher의 `ref/orca`/`vendor/dJinn` 서브모듈 관행과 동일한 개념).
- **왜 독립 docker-compose 서비스로 안 하나(트레이드오프 인지, 사용자가 명시적으로
  결정)**: `doil-webssh`는 정확히 반대 이유("Isolated WebSSH relay — survives
  doil-sb rebuilds")로 분리돼 있다 — doil-sb를 재배포하면 이 페이지도 같이 끊긴다.
  사용자가 이 트레이드오프를 인지한 상태에서, doil-sb의 기존 인증 체계를 그대로
  재사용하는 이득이 더 크다고 판단해 확정함. 재검토 불필요 — 이미 결정됨.

### 2. 보안: 2단 게이트 (직렬, 둘 다 통과해야 함)

**게이트 1 — 앱 레벨 인증(ID/PW, 최고관리자 전용)**
- doil-sb의 기존 `auth.js`를 **그대로 재사용**(복제 아님, live import):
  ```js
  const { requireRoot } = require('../../auth');   // doil-sb/auth.js
  ```
  `requireRoot`는 이미 존재하는 미들웨어(`auth.js:95`, `module.exports`에 포함
  확인됨) — root 역할의 admin만 통과. 새 인증 로직을 만들 필요 없음.
- doil-sb의 관리자 로그인(scrypt 해시 + opaque bearer token, 1시간 TTL, IP 기반
  로그인 실패 rate-limit)을 그대로 물려받는다 — orca 페이지 전용 로그인 화면 불필요,
  기존 `/admin` 로그인을 통과한 세션이면 바로 접근 가능.

**게이트 2 — 네트워크 레벨(호스트 IP 일치 = VPN 필수)**
- 클라이언트가 doil-sb 호스트 자신의 IP(사용자의 VPN 토폴로지 상, VPN으로 접속했을
  때만 관측되는 IP)와 **일치할 때만** 허용. 이 미들웨어는 orca 라우트에만 적용
  (doil-sb의 다른 페이지들은 영향 없음).
- `auth.js`에 이미 `clientIp(req)` 헬퍼가 있음(`auth.js:73`, XFF 파싱) — 단,
  **현재 export 안 됨**(`module.exports`에 없음 — 확인됨: `{ router, requireToken,
  requireRoot, validToken, tokenInfo, seedFromEnv }`뿐). 구현 시 `auth.js`의
  `module.exports`에 `clientIp` 한 줄 추가해서 재사용하거나, `orca-web` 자체에
  똑같은 XFF 파싱 로직을 작은 헬퍼로 복제(택일, 구현 세션 판단).
- **⚠️ OPEN — 구현 전 사용자에게 실제 값 확인 필요**: "host IP"가 정확히 어떤 값인지
  (VPN 클라이언트 IP 대역, 혹은 doil-sb 컨테이너가 관측하는 특정 고정 IP 하나)를
  사용자의 실제 VPN 네트워크 구성에서 받아와야 한다 — 이 문서엔 하드코딩 안 함.
  구현 세션에서 `.env`의 `ORCA_ALLOWED_IP`(혹은 CIDR) 같은 환경변수로 주입받는 걸
  권장.
- **미들웨어 순서**: IP 체크(게이트 2)를 **먼저**, `requireRoot`(게이트 1)를 그
  다음에 — VPN 밖에서 오는 요청은 인증 로직 자체에 닿기 전에 즉시 403.
  ```js
  router.use('/orca', requireHostIp, requireRoot, orcaRoutes);
  ```

### 3. 프로토콜 — `doil-webssh` 패턴 계승, ssh2 → (node-pty 또는 child_process)

이전 라운드에서 `doil-webssh/server.js`(132줄) 분석 완료, 재사용 방향 확정:

| doil-webssh 원본 | orca-web 대응 |
|---|---|
| 전용 네임스페이스(`/ssh`) | doil-sb의 기존 `io`에 신규 네임스페이스(예: `/orca`) 추가 — `dobisBridge.js`가 `/dobis`+`/dobis-worker` 쓰는 것과 같은 방식으로 `io.of('/orca')` |
| `ssh:start {username,password,cols,rows}` | 자격증명 불필요(로컬 프로세스라 로그인 스텝 없음) — `orca:start {cols,rows}`만 |
| `ssh2.Client().connect()` → `conn.shell()` | `node-pty.spawn(...)` (⚠️ OPEN 참고) |
| `ssh:data`(양방향), `ssh:resize`, `ssh:end` | 이름만 `orca:data`/`orca:resize`/`orca:end`로 바꿔 그대로 |
| SFTP 업/다운로드(`ssh:upload`/`ssh:download`) | 로컬 프로세스라 SFTP 불필요 — 필요하면 그냥 `fs` 직접 read/write(더 단순) |
| `tmux new-session` 자동 주입(원격 세션 생존용) | 로컬 프로세스는 Node 서버가 살아있는 한 프로세스도 살아있음 — tmux 불필요. 대신 "소켓 끊겨도 프로세스는 안 죽인다"는 규율을 명시적으로 넣어야 함(disconnect 시 바로 kill하면 안 됨 — 재접속 시 재사용) |
| 프론트엔드(xterm.js 추정, 미확인) | 그대로 재사용 가능한 부분(브라우저 쪽은 코드 미확인 — 구현 세션에서 doil-webssh의 프론트엔드 정적 파일도 확인 권장) |

### 4. ⚠️ OPEN — "orca"가 정확히 뭘 구동하는지 (구현 착수 전 필수 해소)

`ref/orca`(void-ai-launcher에 vendored)는 **Electron 데스크톱 GUI 앱**이다.
`node-pty`는 텍스트 터미널 프로세스를 감싸는 것이라 GUI 앱의 화면을 가져올 수
없다(stdout 로그만 잡힘, 렌더링 안 됨). 구현 세션 시작 전에 다음 중 뭘 의미하는지
확정해야 한다:
- (a) orca와 관련된 **CLI/터미널 세션**(node-pty로 자연스럽게 해결)
- (b) 정말로 Electron GUI를 원격 표시하려는 것이라면 — 이건 VNC/원격 데스크톱
  프로토콜(예: noVNC) 영역이라 이 문서의 socket.io+node-pty 설계 전체가 안 맞음,
  완전히 다른 접근 필요
- (c) 그 외 — 사용자에게 재확인

## 파일/모듈 구조 (제안)

```
orca-web/
  package.json          # deps: node-pty (또는 (b)의 경우 다른 것), 그 외는 doil-sb의 io/express 인스턴스를 주입받으므로 자체 express/socket.io 불필요
  index.js              # module.exports = { registerOrcaWeb(app, io) { ... } }
  lib/
    ptyBridge.js         # node-pty spawn + I/O 릴레이 (doil-webssh server.js의 ssh2 핸들러 부분 대응)
    ipGate.js             # requireHostIp 미들웨어 (clientIp 재사용 또는 자체 구현)
  public/
    orca.html             # xterm.js 기반 단말 페이지 (doil-webssh 프론트엔드 확인 후 이식)
  plan.md                # (이 문서)
```

## doil-sb 쪽 통합 지점 (확인된 정확한 위치)

- `.gitmodules`: `doil-sb/submodules/orca-web` 서브모듈 추가.
- `app.js:466` 부근(`registerDobis(io)` 다음 줄)에
  `require('./submodules/orca-web').registerOrcaWeb(app, io);` 추가.
- `auth.js` `module.exports`(192행)에 `clientIp` 추가(게이트 2용, 위 참고).
- **nginx 설정 변경 불필요** — doil-sb의 기존 `/sb/socket.io` 경로/포트를 그대로
  타므로 새 location block이 필요 없음(독립 서비스안이었다면 필요했을 부분 — 이
  결정의 실질적 이득).

## 다음 세션 시작 체크리스트

1. **"orca" 정의 확정**(위 ⚠️ OPEN §4) — 사용자에게 직접 재확인.
2. **host IP/CIDR 실값 확인**(위 ⚠️ OPEN §2) — 사용자의 VPN 구성에서.
3. `doil-webssh`의 프론트엔드 정적 파일(`public/` 등, 이번 라운드엔 미확인) 확인 —
   xterm.js 초기화 코드를 그대로 이식 가능한지.
4. `orca-web` 리포 git init + `doil-sb`에 서브모듈로 add.
5. `lib/ptyBridge.js` 구현(§3 표 기준), `lib/ipGate.js` 구현(§2 기준),
   `index.js`의 `registerOrcaWeb(app, io)` 구현, `doil-sb/app.js` 통합 한 줄 추가.
6. 로컬에서 VPN 연결/미연결 상태 각각 실측 테스트(게이트 2가 실제로 막는지),
   root 아닌 계정으로 접근 시도(게이트 1이 막는지) 확인.
