// 게이트 2 — 네트워크 레벨: VPN 동일 서브넷일 때만 허용.
// 허용 목록은 .env 주입: ORCA_ALLOWED_IP(콤마 구분 IP) / ORCA_ALLOWED_CIDR(콤마 구분 IPv4 CIDR).
// 추가로: 같은 집 네트워크(공유기 뒤)에서 doil.me 공인 도메인으로 접속한 트래픽도 허용(OR).
//
// 시행착오 기록 — "클라이언트 외부 IP == 서버 자신의 외부 IP" 비교로 시도했으나 실측 결과
// 실패: 도커가 퍼블리시 포트에 거는 iptables NAT이 같은 LAN에서 나가서 hairpin으로 돌아오는
// 트래픽을 전부 "도커 브리지 게이트웨이 주소"로 마스커레이드해버려(호스트 자신이 self-ping
// 해도 동일), 진짜 공인 IP(api.ipify.org로 조회한 값)엔 절대 도달 못 함. 반대로 이 마스커레이드
// 자체가 "같은 LAN에서 왔다"는 확실한 신호이므로, 클라이언트 IP가 이 컨테이너의 **기본 게이트웨이
// 주소**(하드코딩 아님 — /proc/net/route에서 매번 동적으로 읽음, dev-net 서브넷이 바뀌어도 대응)와
// 같으면 허용한다.
//
// 스푸핑 주의: 이 판정이 안전하려면 클라이언트가 "IP를 172.18.0.1이라고 헤더로 주장"하는 걸로
// 통과하면 안 된다 — auth.js의 clientIp()가 X-Real-IP(nginx가 $remote_addr로 직접 설정, 클라이언트
// 조작 불가)를 우선하도록 이미 고쳐뒀으므로, 여기 들어오는 ip는 신뢰 가능한 값이어야 한다.
const fs = require('fs');

function getDefaultGateway() {
  try {
    const lines = fs.readFileSync('/proc/net/route', 'utf8').trim().split('\n').slice(1);
    for (const line of lines) {
      const cols = line.trim().split(/\s+/);
      const destHex = cols[1], gatewayHex = cols[2];
      if (destHex === '00000000' && gatewayHex && gatewayHex !== '00000000') {
        const buf = Buffer.from(gatewayHex, 'hex');
        return [buf[3], buf[2], buf[1], buf[0]].join('.');   // /proc/net/route는 호스트 바이트순(리틀엔디안)
      }
    }
  } catch (e) {
    console.warn('[orca ipGate] 기본 게이트웨이 조회 실패:', e.message);
  }
  return null;
}

function normalizeIp(ip) {
  ip = String(ip || '').trim();
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);   // IPv4-mapped IPv6
  return ip;
}

function ipv4ToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const v = Number(p);
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    n = (n * 256) + v;
  }
  return n;
}

function inCidr(ip, cidr) {
  const [base, bitsStr] = cidr.split('/');
  const bits = Number(bitsStr);
  const ipInt = ipv4ToInt(ip);
  const baseInt = ipv4ToInt(base);
  if (ipInt == null || baseInt == null || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  if (bits === 0) return true;
  const mask = (0xFFFFFFFF << (32 - bits)) >>> 0;
  return ((ipInt & mask) >>> 0) === ((baseInt & mask) >>> 0);
}

async function allowedIp(ip) {
  ip = normalizeIp(ip);

  const gw = getDefaultGateway();
  console.log(`[orca ipGate] client=${ip} gateway=${gw}`);
  if (gw && ip === gw) return true;   // 같은 집 네트워크 hairpin(도커 게이트웨이로 관측됨)

  const ips = (process.env.ORCA_ALLOWED_IP || '').split(',').map(s => s.trim()).filter(Boolean);
  const cidrs = (process.env.ORCA_ALLOWED_CIDR || '').split(',').map(s => s.trim()).filter(Boolean);
  if (!ips.length && !cidrs.length) return false;   // 미설정 = 전부 차단
  if (ips.includes(ip)) return true;
  return cidrs.some(c => inCidr(ip, c));
}

module.exports = { allowedIp, normalizeIp };
