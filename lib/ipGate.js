// 게이트 2 — 네트워크 레벨: VPN 동일 서브넷일 때만 허용.
// 허용 목록은 .env 주입: ORCA_ALLOWED_IP(콤마 구분 IP) / ORCA_ALLOWED_CIDR(콤마 구분 IPv4 CIDR).
// 둘 다 비어 있으면 fail-closed(전부 차단).

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
  const ips = (process.env.ORCA_ALLOWED_IP || '').split(',').map(s => s.trim()).filter(Boolean);
  const cidrs = (process.env.ORCA_ALLOWED_CIDR || '').split(',').map(s => s.trim()).filter(Boolean);
  if (!ips.length && !cidrs.length) return false;   // 미설정 = 전부 차단
  if (ips.includes(ip)) return true;
  return cidrs.some(c => inCidr(ip, c));
}

module.exports = { allowedIp, normalizeIp };
