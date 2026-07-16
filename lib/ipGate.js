// 게이트 2 — 네트워크 레벨: VPN 동일 서브넷일 때만 허용.
// 허용 목록은 .env 주입: ORCA_ALLOWED_IP(콤마 구분 IP) / ORCA_ALLOWED_CIDR(콤마 구분 IPv4 CIDR).
// 추가로: 클라이언트 외부 IP == 이 서버(gw) 자신의 외부 IP도 허용(OR) — 포트포워딩 홈서버
// 특성상 같은 공유기 뒤에서 나가면 hairpin NAT으로 클라이언트도 서버와 동일 공인 IP로 관측되기
// 때문. host 자신의 외부 IP는 api.ipify.org로 조회한다 — doil.me 자신을 도메인으로 찔러보는
// 방식은 실측 결과 도커가 퍼블리시 포트에 거는 iptables NAT 때문에(호스트에서 직접 찔러도
// 동일) 브리지 게이트웨이 주소만 나와 못 씀. 캐싱 없음(체크 빈도가 낮아 매번 조회해도 무방).
const https = require('https');

const SELF_IP_LOOKUP_URL = 'https://api.ipify.org';

function fetchHostIp() {
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

  try {
    const hostIp = normalizeIp(await fetchHostIp());
    console.log(`[orca ipGate] client=${ip} host=${hostIp}`);
    if (hostIp && ip === hostIp) return true;   // gw와 같은 외부 IP = 같은 네트워크로 간주
  } catch (e) {
    console.warn('[orca ipGate] host 외부 IP 조회 실패(이 조건은 건너뜀):', e.message);
  }

  const ips = (process.env.ORCA_ALLOWED_IP || '').split(',').map(s => s.trim()).filter(Boolean);
  const cidrs = (process.env.ORCA_ALLOWED_CIDR || '').split(',').map(s => s.trim()).filter(Boolean);
  if (!ips.length && !cidrs.length) return false;   // 미설정 = 전부 차단
  if (ips.includes(ip)) return true;
  return cidrs.some(c => inCidr(ip, c));
}

module.exports = { allowedIp, normalizeIp };
