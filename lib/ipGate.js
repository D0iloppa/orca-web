// 게이트 2 — 네트워크 레벨: VPN 동일 서브넷일 때만 허용.
// 허용 목록은 .env 주입: ORCA_ALLOWED_IP(콤마 구분 IP) / ORCA_ALLOWED_CIDR(콤마 구분 IPv4 CIDR).
// 추가로: 클라이언트 외부 IP가 이 서버(gw) 자신의 외부 IP와 같으면 허용 — 포트포워딩 홈서버
// 특성상 같은 공유기 뒤(=동일 네트워크)에서 나가면 클라이언트도 서버와 같은 공인 IP로 보이기
// 때문(hairpin NAT). 둘 다 비어 있고 자체 IP도 아직 못 구했으면 fail-closed(전부 차단).
const https = require('https');

const SELF_IP_LOOKUP_URL = 'https://api.ipify.org';
const SELF_IP_REFRESH_MS = 10 * 60 * 1000;   // 10분마다 재확인 (동적 공인 IP 대비)

let selfIp = null;

function fetchSelfIp() {
  return new Promise((resolve, reject) => {
    const req = https.get(SELF_IP_LOOKUP_URL, { timeout: 5000 }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => resolve(data.trim()));
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('timeout')));
  });
}

async function refreshSelfIp() {
  try {
    const ip = normalizeIp(await fetchSelfIp());
    if (ipv4ToInt(ip) != null) selfIp = ip;
  } catch (e) {
    console.warn('[orca ipGate] 자체 외부 IP 조회 실패(다음 주기에 재시도):', e.message);
  }
}

refreshSelfIp();
setInterval(refreshSelfIp, SELF_IP_REFRESH_MS).unref();

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

function allowedIp(ip) {
  ip = normalizeIp(ip);
  if (selfIp && ip === selfIp) return true;   // gw와 같은 외부 IP = 같은 네트워크로 간주
  const ips = (process.env.ORCA_ALLOWED_IP || '').split(',').map(s => s.trim()).filter(Boolean);
  const cidrs = (process.env.ORCA_ALLOWED_CIDR || '').split(',').map(s => s.trim()).filter(Boolean);
  if (!ips.length && !cidrs.length) return false;   // 미설정 = 전부 차단
  if (ips.includes(ip)) return true;
  return cidrs.some(c => inCidr(ip, c));
}

module.exports = { allowedIp, normalizeIp };
