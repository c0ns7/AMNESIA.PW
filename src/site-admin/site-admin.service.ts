import {
  Inject,
  Injectable,
  Optional,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import * as crypto from 'crypto';
import * as jwt from 'jsonwebtoken';
import { Request } from 'express';
import { Pool, RowDataPacket } from 'mysql2/promise';
import { VPN_DB_POOL } from '../database/database.module';
import { SiteAdminLoginDto } from './dto/site-admin-login.dto';
import { SiteAdminVerifyOtpDto } from './dto/site-admin-verify-otp.dto';

const SITE_ADMIN_LOGIN = 'root';
/** SHA-256 от строки пароля FreeziWay228 (UTF-8), hex */
const SITE_ADMIN_PASSWORD_SHA256 =
  '10041a800903de6c92770f22f8307955bd92eb246a71909b75d0acf147ed9b51';

const COOKIE_NAME = 'amnesia_site_admin';
const JWT_MAX_AGE_MS = 8 * 60 * 60 * 1000;
const OTP_TTL_MS = 10 * 60 * 1000;
const DEFAULT_NOTIFY_CHAT_ID = 755944391;

interface FranchiseRow extends RowDataPacket {
  id: number;
  owner_user_id: number;
  bot_username: string | null;
  is_active: number | boolean;
  share_percent: string | number | null;
  created_at: Date;
  owner_username: string | null;
  revenue: string | number | null;
  franchise_profit: string | number | null;
  withdrawn_reserved: string | number | null;
  withdrawn_approved: string | number | null;
}

interface PendingOtp {
  otp: string;
  expiresAt: number;
}

@Injectable()
export class SiteAdminService {
  private readonly pendingOtp = new Map<string, PendingOtp>();

  constructor(@Optional() @Inject(VPN_DB_POOL) private readonly vpnPool: Pool | null) {}

  getCookieName(): string {
    return COOKIE_NAME;
  }

  private jwtSecret(): string {
    const s =
      process.env.SITE_ADMIN_JWT_SECRET?.trim() ||
      process.env.JWT_SECRET?.trim() ||
      process.env.SESSION_SECRET?.trim() ||
      '';
    if (process.env.NODE_ENV === 'production' && (!s || s.length < 32)) {
      throw new Error(
        'SITE_ADMIN_JWT_SECRET (или JWT_SECRET) ≥ 32 символов обязателен в production',
      );
    }
    return s || 'dev-only-site-admin-secret-change-me';
  }

  private hashPassword(plain: string): string {
    return crypto.createHash('sha256').update(plain, 'utf8').digest('hex');
  }

  private pruneOtp(): void {
    const now = Date.now();
    for (const [k, v] of this.pendingOtp.entries()) {
      if (v.expiresAt < now) this.pendingOtp.delete(k);
    }
  }

  async requestLoginStep1(
    dto: SiteAdminLoginDto,
  ): Promise<{ sessionId: string; message: string }> {
    if (dto.login.trim() !== SITE_ADMIN_LOGIN) {
      throw new UnauthorizedException('Неверный логин или пароль');
    }
    if (this.hashPassword(dto.password) !== SITE_ADMIN_PASSWORD_SHA256) {
      throw new UnauthorizedException('Неверный логин или пароль');
    }
    this.pruneOtp();
    const sessionId = crypto.randomBytes(24).toString('hex');
    const otp = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
    this.pendingOtp.set(sessionId, { otp, expiresAt: Date.now() + OTP_TTL_MS });
    await this.sendOtpTelegram(otp);
    return {
      sessionId,
      message: 'Код отправлен в Telegram основного бота.',
    };
  }

  private async sendOtpTelegram(code: string): Promise<void> {
    const token =
      process.env.AMNESIA_MAIN_BOT_TOKEN?.trim() ||
      process.env.TELEGRAM_BOT_TOKEN?.trim() ||
      process.env.BOT_TOKEN?.trim() ||
      '';
    if (!token) {
      throw new ServiceUnavailableException(
        'Не задан AMNESIA_MAIN_BOT_TOKEN (или TELEGRAM_BOT_TOKEN) для отправки кода.',
      );
    }
    const chatId = Number(
      process.env.SITE_ADMIN_NOTIFY_TELEGRAM_ID || DEFAULT_NOTIFY_CHAT_ID,
    );
    const text = [
      '<b>AMNESIA.PW — вход в /admin</b>',
      '',
      `Код: <code>${code}</code>`,
      '',
      'Действителен 10 минут. Если это не вы — смените пароль и проверьте .env.',
    ].join('\n');
    const url = `https://api.telegram.org/bot${token}/sendMessage`;
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        text,
        parse_mode: 'HTML',
      }),
    });
    const data = (await res.json().catch(() => ({}))) as { ok?: boolean; description?: string };
    if (!res.ok || !data.ok) {
      throw new ServiceUnavailableException(
        data.description || 'Не удалось отправить код в Telegram',
      );
    }
  }

  verifyOtpAndSignJwt(dto: SiteAdminVerifyOtpDto): string {
    this.pruneOtp();
    const pending = this.pendingOtp.get(dto.sessionId);
    if (!pending || pending.expiresAt < Date.now()) {
      throw new UnauthorizedException('Сессия истекла. Запросите вход снова.');
    }
    if (pending.otp !== dto.code.trim()) {
      throw new UnauthorizedException('Неверный код');
    }
    this.pendingOtp.delete(dto.sessionId);
    return jwt.sign({ role: 'site-admin', v: 1 }, this.jwtSecret(), {
      expiresIn: Math.floor(JWT_MAX_AGE_MS / 1000),
    });
  }

  verifyJwtFromRequest(req: Request): boolean {
    const token = req.cookies?.[COOKIE_NAME] as string | undefined;
    if (!token) return false;
    try {
      const p = jwt.verify(token, this.jwtSecret()) as { role?: string };
      return p?.role === 'site-admin';
    } catch {
      return false;
    }
  }

  async getFranchisesDashboard(): Promise<{
    franchises: Array<{
      id: number;
      owner_user_id: number;
      owner_username: string | null;
      bot_username: string | null;
      bot_link: string | null;
      is_active: boolean;
      share_percent: number;
      created_at: string;
      revenue: number;
      franchise_profit: number;
      available_to_withdraw: number;
      withdrawn_approved: number;
      withdrawn_pending: number;
    }>;
    totals: {
      count: number;
      active_count: number;
      revenue: number;
      franchise_profit: number;
      available_to_withdraw: number;
      withdrawn_approved: number;
      withdrawn_pending: number;
    };
  }> {
    if (!this.vpnPool) {
      throw new ServiceUnavailableException(
        'VPN БД не настроена (DB_NAME / VPN_DATABASE в .env).',
      );
    }
    const sql = `
      SELECT f.id, f.owner_user_id, f.bot_username, f.is_active, f.share_percent, f.created_at,
             u.username AS owner_username,
             (SELECT COALESCE(SUM(p.amount), 0) FROM payments p
              WHERE p.franchise_owner_id = f.owner_user_id AND p.status = 'success') AS revenue,
             (SELECT COALESCE(SUM(p.franchise_share_amount), 0) FROM payments p
              WHERE p.franchise_owner_id = f.owner_user_id AND p.status = 'success') AS franchise_profit,
             (SELECT COALESCE(SUM(w.amount), 0) FROM franchise_withdrawals w
              WHERE w.franchise_owner_id = f.owner_user_id AND w.status IN ('pending','approved')) AS withdrawn_reserved,
             (SELECT COALESCE(SUM(w.amount), 0) FROM franchise_withdrawals w
              WHERE w.franchise_owner_id = f.owner_user_id AND w.status = 'approved') AS withdrawn_approved
      FROM franchises f
      INNER JOIN (SELECT owner_user_id, MAX(id) AS mid FROM franchises GROUP BY owner_user_id) latest
        ON f.owner_user_id = latest.owner_user_id AND f.id = latest.mid
      LEFT JOIN users u ON u.user_id = f.owner_user_id
      ORDER BY franchise_profit DESC, f.id DESC
    `;
    const [rows] = await this.vpnPool.query<FranchiseRow[]>(sql);
    const list = (rows || []).map((r) => {
      const revenue = Number(r.revenue) || 0;
      const franchiseProfit = Number(r.franchise_profit) || 0;
      const reserved = Number(r.withdrawn_reserved) || 0;
      const approved = Number(r.withdrawn_approved) || 0;
      const available = Math.max(0, franchiseProfit - reserved);
      const pending = Math.max(0, reserved - approved);
      const uname = r.bot_username
        ? String(r.bot_username).replace(/^@/, '')
        : '';
      return {
        id: r.id,
        owner_user_id: Number(r.owner_user_id),
        owner_username: r.owner_username || null,
        bot_username: r.bot_username || null,
        bot_link: uname ? `https://t.me/${uname}` : null,
        is_active: Boolean(Number(r.is_active)),
        share_percent: Number(r.share_percent) || 50,
        created_at:
          r.created_at instanceof Date
            ? r.created_at.toISOString()
            : String(r.created_at),
        revenue,
        franchise_profit: franchiseProfit,
        available_to_withdraw: available,
        withdrawn_approved: approved,
        withdrawn_pending: pending,
      };
    });
    const totals = list.reduce(
      (acc, f) => {
        acc.revenue += f.revenue;
        acc.franchise_profit += f.franchise_profit;
        acc.available_to_withdraw += f.available_to_withdraw;
        acc.withdrawn_approved += f.withdrawn_approved;
        acc.withdrawn_pending += f.withdrawn_pending;
        if (f.is_active) acc.active_count += 1;
        return acc;
      },
      {
        count: list.length,
        active_count: 0,
        revenue: 0,
        franchise_profit: 0,
        available_to_withdraw: 0,
        withdrawn_approved: 0,
        withdrawn_pending: 0,
      },
    );
    return { franchises: list, totals };
  }
}
