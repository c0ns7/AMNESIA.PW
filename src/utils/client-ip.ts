import { Request } from 'express';

/** Реальный клиент за Cloudflare / reverse proxy (для капчи, rate limit). */
export function getClientIp(req: Request): string | undefined {
  const cf = req.headers['cf-connecting-ip'];
  if (typeof cf === 'string' && cf.trim()) {
    return cf.trim();
  }
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.trim()) {
    const first = xff.split(',')[0]?.trim();
    if (first) return first;
  }
  const ip = req.ip;
  if (typeof ip === 'string' && ip) return ip;
  return undefined;
}
