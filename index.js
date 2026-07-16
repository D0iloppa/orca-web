// orca-web — Orca 데스크톱(별도 오픈소스 Electron 앱) 원격 접속 웹 클라이언트의 백엔드.
// 브라우저(관리자 콘솔 "orca" 뷰) ↔ socket.io 네임스페이스 /orca ↔ (E2EE ws) ↔ Orca 데스크톱.
// E2EE(nacl)는 doil-sb ↔ 데스크톱 구간에서 종단 — 브라우저↔doil-sb 구간은 기존 TLS(+2단 게이트).
const { tokenInfo, clientIp } = require('../../auth');   // doil-sb/auth.js live import
const { allowedIp } = require('./lib/ipGate');
const { OrcaClient, parsePairingCode } = require('./lib/orcaClient');

function handshakeIp(socket) {
  // auth.clientIp 재사용 — socket.io handshake를 req 모양({headers, ip})으로 넘긴다
  return clientIp({ headers: socket.handshake.headers, ip: socket.handshake.address });
}

function registerOrcaWeb(app, io) {
  const nsp = io.of('/orca');

  // 게이트 2 (먼저) — VPN 서브넷 IP 체크
  nsp.use((s, next) => {
    if (allowedIp(handshakeIp(s))) return next();
    next(new Error('forbidden: VPN 네트워크에서만 접근 가능합니다'));
  });
  // 게이트 1 — root 관리자 토큰
  nsp.use((s, next) => {
    const t = s.handshake.auth && s.handshake.auth.token;
    const info = tokenInfo(t, false);
    if (info && info.role === 'root') return next();
    next(new Error('unauthorized: 루트 관리자만 가능합니다'));
  });

  nsp.on('connection', (socket) => {
    let client = null;   // 소켓당 데스크톱 연결 1개 (LAN 직결 단일 세션)

    const dropClient = () => { if (client) { client.onClose = null; client.close(); client = null; } };

    socket.on('orca:pair', async (m = {}, ack) => {
      try {
        const pairing = parsePairingCode(m.code);
        dropClient();
        client = new OrcaClient(pairing);
        await client.connect();
        client.onClose = (reason) => { client = null; socket.emit('orca:closed', { reason }); };
        if (typeof ack === 'function') ack({ ok: true, endpoint: pairing.endpoint });
      } catch (e) {
        dropClient();
        if (typeof ack === 'function') ack({ ok: false, error: e.message });
      }
    });

    // 일반 RPC 패스스루 — 데스크톱 응답 envelope 그대로 반환
    socket.on('orca:rpc', async (m = {}, ack) => {
      if (typeof ack !== 'function') return;
      if (!client) return ack({ ok: false, error: '데스크톱과 페어링되지 않았습니다' });
      try { ack(await client.rpc(m.method, m.params)); }
      catch (e) { ack({ ok: false, error: e.message }); }
    });

    // 스트리밍 RPC (terminal.subscribe) — push를 orca:stream 이벤트로 중계
    socket.on('orca:subscribe', (m = {}, ack) => {
      if (typeof ack !== 'function') return;
      if (!client) return ack({ ok: false, error: '데스크톱과 페어링되지 않았습니다' });
      try {
        const id = client.rpcStream('terminal.subscribe', { terminal: m.terminal }, (msg) => socket.emit('orca:stream', msg));
        ack({ ok: true, id });
      } catch (e) { ack({ ok: false, error: e.message }); }
    });

    socket.on('orca:unsubscribe', async (m = {}, ack) => {
      if (!client) { if (typeof ack === 'function') ack({ ok: false, error: '연결 없음' }); return; }
      if (m.id) client.dropStream(m.id);
      try { const r = await client.rpc('terminal.unsubscribe', { terminal: m.terminal }); if (typeof ack === 'function') ack(r); }
      catch (e) { if (typeof ack === 'function') ack({ ok: false, error: e.message }); }
    });

    socket.on('orca:unpair', () => dropClient());
    socket.on('disconnect', () => dropClient());
  });

  console.log('🐋 orca-web registered — socket.io namespace /orca (게이트: IP → root)');
}

module.exports = { registerOrcaWeb };
