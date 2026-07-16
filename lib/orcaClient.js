// Orca 데스크톱 relay 프로토콜 클라이언트 (LAN 직결 전용, E2EE v2 relay-fallback 미지원)
// 페어링 코드 → ws 직결 → X25519(nacl.box) 핸드셰이크 → 암호화 RPC.
const crypto = require('crypto');
const WebSocket = require('ws');
const nacl = require('tweetnacl');

const CONNECT_TIMEOUT_MS = 10000;   // ws open + e2ee 핸드셰이크 전체
const RPC_TIMEOUT_MS = 15000;
const SEND_TEXT_MAX = 256 * 1024;   // terminal.send text 상한 (프로토콜 스펙)
const MIN_PROTOCOL_VERSION = 2;     // 페어링 코드 v 필드 기준

function b64ToBytes(s) {
  return new Uint8Array(Buffer.from(s, 'base64'));
}

// `orca://pair?code=<base64url(JSON)>` 또는 순수 code 문자열 → 페어링 정보
function parsePairingCode(input) {
  let code = String(input || '').trim();
  if (!code) throw new Error('빈 페어링 코드');
  const m = code.match(/[?&]code=([^&\s]+)/);
  if (m) code = decodeURIComponent(m[1]);
  let json;
  try {
    json = Buffer.from(code.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
  } catch (e) {
    throw new Error('페어링 코드 base64 디코드 실패');
  }
  let p;
  try { p = JSON.parse(json); } catch (e) { throw new Error('페어링 코드 JSON 파싱 실패'); }
  if (!p.endpoint || !p.deviceToken || !p.publicKeyB64) {
    throw new Error('페어링 코드에 endpoint/deviceToken/publicKeyB64 필드가 없습니다');
  }
  if (typeof p.v === 'number' && p.v < MIN_PROTOCOL_VERSION) {
    throw new Error(`지원하지 않는 프로토콜 버전 v${p.v} (최소 v${MIN_PROTOCOL_VERSION})`);
  }
  // relay 필드는 무시(LAN 직결만 지원) — 있으면 그냥 endpoint 직결 시도
  return p;
}

class OrcaClient {
  constructor(pairing) {
    this.pairing = pairing;
    this.deviceToken = pairing.deviceToken;
    this.serverPub = b64ToBytes(pairing.publicKeyB64);
    this.keys = nacl.box.keyPair();
    this.sharedKey = null;
    this.authed = false;
    this.ws = null;
    this.pending = new Map();   // id -> {resolve, reject, timer}
    this.streams = new Map();   // id -> onEvent(msg)  (스트리밍 RPC — pending에서 제거하지 않음)
    this.onClose = null;        // (reason) => void
  }

  connect() {
    return new Promise((resolve, reject) => {
      let settled = false;
      const fail = (err) => { if (!settled) { settled = true; clearTimeout(timer); this.close(); reject(err); } };
      const timer = setTimeout(() => fail(new Error(`연결/핸드셰이크 타임아웃 (${CONNECT_TIMEOUT_MS / 1000}s) — ${this.pairing.endpoint}`)), CONNECT_TIMEOUT_MS);

      let ws;
      try { ws = new WebSocket(this.pairing.endpoint); } catch (e) { return fail(e); }
      this.ws = ws;

      ws.on('open', () => {
        // 1) 평문 hello — 내 ephemeral pubkey 전달
        ws.send(JSON.stringify({ type: 'e2ee_hello', publicKeyB64: Buffer.from(this.keys.publicKey).toString('base64') }));
      });
      ws.on('error', (e) => fail(new Error(`웹소켓 오류: ${e.message}`)));
      ws.on('close', (code, reasonBuf) => {
        const reason = `연결 종료 (code=${code}${reasonBuf && reasonBuf.length ? ', ' + reasonBuf : ''})`;
        if (!settled) return fail(new Error(reason));
        this._teardown(reason);
      });
      ws.on('message', (raw) => {
        try {
          if (!this.sharedKey) {
            // 핸드셰이크 단계 — 평문
            const msg = JSON.parse(raw.toString('utf8'));
            if (msg.type === 'e2ee_ready') {
              this.sharedKey = nacl.box.before(this.serverPub, this.keys.secretKey);
              this._send({ type: 'e2ee_auth', deviceToken: this.deviceToken });
            } else if (msg.type === 'e2ee_error') {
              fail(new Error(`핸드셰이크 거부: ${msg.message || JSON.stringify(msg)}`));
            }
            return;
          }
          const msg = this._decrypt(raw);
          if (!this.authed) {
            if (msg.type === 'e2ee_authenticated') {
              this.authed = true;
              // 방어적 버전 체크 — 필드가 있을 때만 (TODO: 실측 후 정확한 위치 확정)
              if (typeof msg.protocolVersion === 'number' && msg.protocolVersion < MIN_PROTOCOL_VERSION) {
                return fail(new Error(`데스크톱 프로토콜 버전 ${msg.protocolVersion} — 최소 ${MIN_PROTOCOL_VERSION} 필요`));
              }
              settled = true; clearTimeout(timer); resolve();
            } else if (msg.type === 'e2ee_error') {
              fail(new Error(`인증 실패: ${msg.message || JSON.stringify(msg)}`));
            }
            return;
          }
          this._route(msg);
        } catch (e) {
          if (!settled) fail(new Error(`메시지 처리 오류: ${e.message}`));
        }
      });
    });
  }

  _send(obj) {
    // 24바이트 랜덤 nonce + nacl.box.after → base64 텍스트 프레임
    const nonce = crypto.randomBytes(nacl.box.nonceLength);
    const boxed = nacl.box.after(new Uint8Array(Buffer.from(JSON.stringify(obj), 'utf8')), new Uint8Array(nonce), this.sharedKey);
    this.ws.send(Buffer.concat([nonce, Buffer.from(boxed)]).toString('base64'));
  }

  _decrypt(raw) {
    const buf = Buffer.from(raw.toString('utf8'), 'base64');
    const nonce = new Uint8Array(buf.subarray(0, nacl.box.nonceLength));
    const boxed = new Uint8Array(buf.subarray(nacl.box.nonceLength));
    const opened = nacl.box.open.after(boxed, nonce, this.sharedKey);
    if (!opened) throw new Error('복호화 실패 (nacl.box.open)');
    return JSON.parse(Buffer.from(opened).toString('utf8'));
  }

  _route(msg) {
    const id = msg.id;
    if (id && this.streams.has(id)) { this.streams.get(id)(msg); return; }   // 스트리밍 — pending 제거 금지
    if (id && this.pending.has(id)) {
      const p = this.pending.get(id);
      this.pending.delete(id);
      clearTimeout(p.timer);
      p.resolve(msg);
    }
    // 그 외(서버 push 등)는 현재 스코프에서 무시
  }

  _request(method, params) {
    const id = crypto.randomUUID();
    this._send({ id, deviceToken: this.deviceToken, method, params });
    return id;
  }

  // 일반 RPC — 응답 envelope({ok, result|error, _meta})를 그대로 resolve
  rpc(method, params) {
    if (!this.authed) return Promise.reject(new Error('미인증 상태'));
    if (method === 'terminal.send') {
      params = Object.assign({ client: { id: this.deviceToken, type: 'mobile' } }, params);
      if (Buffer.byteLength(String(params.text || ''), 'utf8') > SEND_TEXT_MAX) {
        return Promise.reject(new Error('terminal.send text가 256KiB를 초과합니다'));
      }
    }
    return new Promise((resolve, reject) => {
      const id = this._request(method, params);
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`RPC 타임아웃: ${method} (${RPC_TIMEOUT_MS / 1000}s)`));
      }, RPC_TIMEOUT_MS);
      this.pending.set(id, { resolve, reject, timer });
    });
  }

  // 스트리밍 RPC (terminal.subscribe 등) — 최초 응답 포함 같은 id의 모든 push를 onEvent로 전달
  rpcStream(method, params, onEvent) {
    if (!this.authed) throw new Error('미인증 상태');
    const id = this._request(method, params);
    this.streams.set(id, onEvent);
    return id;
  }

  dropStream(id) { this.streams.delete(id); }

  _teardown(reason) {
    for (const [, p] of this.pending) { clearTimeout(p.timer); p.reject(new Error(reason)); }
    this.pending.clear();
    this.streams.clear();
    this.authed = false;
    if (this.onClose) { const cb = this.onClose; this.onClose = null; cb(reason); }
  }

  close() {
    if (this.ws) { try { this.ws.close(); } catch (e) { } this.ws = null; }
    this._teardown('클라이언트에서 연결 종료');
  }
}

module.exports = { OrcaClient, parsePairingCode };
