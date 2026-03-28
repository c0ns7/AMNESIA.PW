import {
  BadRequestException,
  ConflictException,
  Inject,
  Injectable,
  NotFoundException,
  OnModuleInit,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import * as jwt from 'jsonwebtoken';
import { ResultSetHeader } from 'mysql2';
import { Pool, RowDataPacket } from 'mysql2/promise';
import { MYSQL_POOL } from '../database/database.module';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { TelegramWidgetDto } from './dto/telegram-widget.dto';
import { SessionUser } from './session.types';

interface UserRow extends RowDataPacket {
  id: number;
  username: string;
  password_hash: string;
  telegram_id: number | null;
  telegram_username: string | null;
}

interface AmnesiaJwtPayload {
  sub: number;
  u: string;
}

@Injectable()
export class AuthService implements OnModuleInit {
  constructor(@Inject(MYSQL_POOL) private readonly pool: Pool) {}

  private readonly recaptchaSecret =
    process.env.RECAPTCHA_SECRET_KEY?.trim() ||
    process.env.RECAPTCHA_SECRET?.trim() ||
    '';
  private readonly recaptchaSiteKey =
    process.env.RECAPTCHA_SITE_KEY?.trim() ||
    process.env.RECAPTCHA_SITE?.trim() ||
    '';
  private readonly recaptchaVerifyUrl =
    'https://www.google.com/recaptcha/api/siteverify';
  private readonly recaptchaMinScore = Number(
    process.env.RECAPTCHA_MIN_SCORE || 0.5,
  );

  private readonly jwtSecret =
    process.env.JWT_SECRET?.trim() ||
    process.env.SESSION_SECRET?.trim() ||
    'change-me-in-production';
  private readonly jwtExpiresMs = 7 * 24 * 60 * 60 * 1000;
  private readonly cookieName = 'amnesia_auth';

  private readonly webTelegramBotToken =
    process.env.WEB_TELEGRAM_BOT_TOKEN?.trim() || '';

  async onModuleInit() {
    await this.ensureSchema();
  }

  private normalizeUsername(raw: string): string {
    return raw.trim().toLowerCase();
  }

  getCookieName() {
    return this.cookieName;
  }

  getJwtMaxAgeMs() {
    return this.jwtExpiresMs;
  }

  private ensureCaptchaConfigured(): void {
    if (!this.recaptchaSecret || !this.recaptchaSiteKey) {
      throw new ServiceUnavailableException(
        'Капча временно недоступна. Попробуйте позже.',
      );
    }
  }

  getCaptchaConfig() {
    this.ensureCaptchaConfigured();
    return {
      siteKey: this.recaptchaSiteKey,
      version: 'v3',
      minScore: this.recaptchaMinScore,
    };
  }

  private async verifyCaptcha(
    captchaToken: string,
    remoteIp?: string,
    expectedAction?: string,
  ): Promise<void> {
    this.ensureCaptchaConfigured();
    const token = String(captchaToken || '').trim();
    if (!token) {
      throw new BadRequestException('Подтвердите, что вы не робот');
    }

    const payload = new URLSearchParams();
    payload.set('secret', this.recaptchaSecret);
    payload.set('response', token);
    if (remoteIp) {
      payload.set('remoteip', remoteIp);
    }

    let response;
    try {
      response = await fetch(this.recaptchaVerifyUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: payload.toString(),
      });
    } catch (_) {
      throw new ServiceUnavailableException(
        'Не удалось проверить капчу. Попробуйте позже.',
      );
    }

    type RecaptchaResult = {
      success?: boolean;
      'error-codes'?: string[];
      score?: number;
      action?: string;
      hostname?: string;
    };

    const result = (await response.json().catch(() => ({}))) as RecaptchaResult;
    if (!response.ok || !result.success) {
      const codes = Array.isArray(result['error-codes'])
        ? result['error-codes'].map((c) => String(c))
        : [];
      const codeSet = new Set(codes);

      if (
        codeSet.has('invalid-input-secret') ||
        codeSet.has('missing-input-secret')
      ) {
        throw new ServiceUnavailableException(
          'Капча настроена неверно (secret key)',
        );
      }
      if (
        codeSet.has('invalid-input-response') ||
        codeSet.has('missing-input-response')
      ) {
        throw new BadRequestException(
          'Подтвердите, что вы не робот' +
            (codes.length ? ` (${codes.join(', ')})` : ''),
        );
      }
      if (codeSet.has('timeout-or-duplicate')) {
        throw new BadRequestException(
          'Подтвердите, что вы не робот (token expired)',
        );
      }

      throw new BadRequestException(
        'Проверка капчи не пройдена' +
          (codes.length ? ` (${codes.join(', ')})` : ''),
      );
    }

    if (expectedAction) {
      const action = typeof result.action === 'string' ? result.action : '';
      if (action !== expectedAction) {
        throw new BadRequestException('Проверка капчи не пройдена');
      }
    }

    const score = typeof result.score === 'number' ? result.score : NaN;
    if (!Number.isFinite(score) || score < this.recaptchaMinScore) {
      throw new BadRequestException(
        `Проверка капчи не пройдена (score=${Number.isFinite(score) ? score.toFixed(2) : '—'})`,
      );
    }
  }

  private async ensureSchema() {
    try {
      await this.pool.execute(
        'ALTER TABLE users ADD COLUMN telegram_id BIGINT NULL',
      );
    } catch (_) {
      /* exists */
    }
    try {
      await this.pool.execute(
        'ALTER TABLE users ADD COLUMN telegram_username VARCHAR(255) NULL',
      );
    } catch (_) {
      /* exists */
    }
    try {
      await this.pool.execute(
        'CREATE UNIQUE INDEX uq_users_telegram_id ON users (telegram_id)',
      );
    } catch (_) {
      /* exists or not */
    }
    await this.pool.execute(`
      CREATE TABLE IF NOT EXISTS telegram_link_tokens (
        id INT AUTO_INCREMENT PRIMARY KEY,
        token VARCHAR(64) NOT NULL UNIQUE,
        user_id INT NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_tlt_user (user_id)
      )
    `);
  }

  createAuthToken(user: SessionUser): string {
    const payload: AmnesiaJwtPayload = { sub: user.id, u: user.username };
    return jwt.sign(payload, this.jwtSecret, {
      expiresIn: Math.floor(this.jwtExpiresMs / 1000),
    });
  }

  verifyAuthToken(token: string): SessionUser | null {
    try {
      const raw = jwt.verify(token, this.jwtSecret);
      const decoded = raw as unknown as AmnesiaJwtPayload;
      if (!decoded?.sub || !decoded?.u) return null;
      return { id: decoded.sub, username: decoded.u };
    } catch {
      return null;
    }
  }

  async register(dto: RegisterDto, remoteIp?: string) {
    await this.verifyCaptcha(dto.captchaToken, remoteIp, 'register');
    if (dto.password !== dto.confirmPassword) {
      throw new BadRequestException('Пароли не совпадают');
    }
    const username = this.normalizeUsername(dto.username);
    const [existing] = await this.pool.execute<RowDataPacket[]>(
      'SELECT id FROM users WHERE username = ? LIMIT 1',
      [username],
    );
    if (existing.length > 0) {
      throw new ConflictException('Этот логин уже занят');
    }
    const passwordHash = await bcrypt.hash(dto.password, 10);
    const [res] = await this.pool.execute<ResultSetHeader>(
      'INSERT INTO users (username, password_hash) VALUES (?, ?)',
      [username, passwordHash],
    );
    const insertId = res.insertId;
    if (!insertId) {
      throw new BadRequestException('Не удалось создать аккаунт');
    }
    const user: SessionUser = { id: insertId, username };
    const token = this.createAuthToken(user);
    return {
      ok: true as const,
      message: 'Регистрация успешна',
      token,
      user,
    };
  }

  async login(dto: LoginDto, remoteIp?: string) {
    await this.verifyCaptcha(dto.captchaToken, remoteIp, 'login');
    const username = this.normalizeUsername(dto.username);
    const [rows] = await this.pool.execute<UserRow[]>(
      'SELECT id, username, password_hash FROM users WHERE username = ? LIMIT 1',
      [username],
    );
    const row = rows[0];
    if (!row) {
      throw new UnauthorizedException('Неверный логин или пароль');
    }
    const match = await bcrypt.compare(dto.password, row.password_hash);
    if (!match) {
      throw new UnauthorizedException('Неверный логин или пароль');
    }
    const user: SessionUser = { id: row.id, username: row.username };
    const token = this.createAuthToken(user);
    return {
      ok: true as const,
      token,
      user,
    };
  }

  async getMe(userId: number) {
    const [rows] = await this.pool.execute<UserRow[]>(
      'SELECT id, username, telegram_id, telegram_username FROM users WHERE id = ? LIMIT 1',
      [userId],
    );
    const row = rows[0];
    if (!row) {
      throw new UnauthorizedException();
    }
    return {
      ok: true as const,
      user: {
        id: row.id,
        username: row.username,
        telegram: row.telegram_id != null
          ? {
              id: String(row.telegram_id),
              username: row.telegram_username || null,
            }
          : null,
      },
    };
  }

  async changePassword(
    userId: number,
    currentPassword: string,
    newPassword: string,
    confirmPassword: string,
  ) {
    if (newPassword !== confirmPassword) {
      throw new BadRequestException('Новые пароли не совпадают');
    }
    if (newPassword.length < 6) {
      throw new BadRequestException('Новый пароль: минимум 6 символов');
    }
    const [rows] = await this.pool.execute<UserRow[]>(
      'SELECT id, password_hash FROM users WHERE id = ? LIMIT 1',
      [userId],
    );
    const row = rows[0];
    if (!row) {
      throw new UnauthorizedException();
    }
    const ok = await bcrypt.compare(currentPassword, row.password_hash);
    if (!ok) {
      throw new BadRequestException('Неверный текущий пароль');
    }
    const hash = await bcrypt.hash(newPassword, 10);
    await this.pool.execute('UPDATE users SET password_hash = ? WHERE id = ?', [
      hash,
      userId,
    ]);
    return { ok: true as const, message: 'Пароль обновлён' };
  }

  private checkTelegramWidgetAuth(data: TelegramWidgetDto): boolean {
    if (!this.webTelegramBotToken) {
      throw new ServiceUnavailableException(
        'Вход через Telegram временно недоступен',
      );
    }
    const { hash, ...rest } = data;
    const entries = Object.entries(rest as Record<string, unknown>)
      .filter(([, v]) => v !== undefined && v !== null && v !== '')
      .map(([k, v]) => [k, String(v)] as [string, string])
      .sort(([a], [b]) => a.localeCompare(b));
    const checkString = entries.map(([k, v]) => `${k}=${v}`).join('\n');
    const secretKey = crypto
      .createHash('sha256')
      .update(this.webTelegramBotToken)
      .digest();
    const hmac = crypto
      .createHmac('sha256', secretKey)
      .update(checkString)
      .digest('hex');
    return hmac === hash;
  }

  /** Telegram Login Widget: вход только если пользователь уже привязал Telegram в ЛК */
  async loginWithTelegramWidget(dto: TelegramWidgetDto) {
    if (!this.checkTelegramWidgetAuth(dto)) {
      throw new BadRequestException('Некорректная подпись Telegram');
    }
    const ageSec = Math.floor(Date.now() / 1000) - dto.auth_date;
    if (ageSec > 86400 || ageSec < -60) {
      throw new BadRequestException('Данные авторизации устарели');
    }
    const tgId = String(dto.id);
    const [rows] = await this.pool.execute<UserRow[]>(
      'SELECT id, username FROM users WHERE telegram_id = ? LIMIT 1',
      [tgId],
    );
    const row = rows[0];
    if (!row) {
      throw new NotFoundException(
        'Аккаунт с привязкой Telegram не найден. Сначала войдите в личный кабинет и привяжите Telegram в разделе «Интеграции».',
      );
    }
    const user: SessionUser = { id: row.id, username: row.username };
    const token = this.createAuthToken(user);
    return { ok: true as const, token, user };
  }

  async startTelegramLink(userId: number) {
    const [rows] = await this.pool.execute<UserRow[]>(
      'SELECT id, telegram_id FROM users WHERE id = ? LIMIT 1',
      [userId],
    );
    const row = rows[0];
    if (!row) {
      throw new UnauthorizedException();
    }
    if (row.telegram_id) {
      throw new BadRequestException('Telegram уже привязан');
    }
    const token = crypto.randomBytes(24).toString('hex');
    const expires = new Date(Date.now() + 15 * 60 * 1000);
    await this.pool.execute('DELETE FROM telegram_link_tokens WHERE user_id = ?', [
      userId,
    ]);
    await this.pool.execute(
      'INSERT INTO telegram_link_tokens (token, user_id, expires_at) VALUES (?, ?, ?)',
      [token, userId, expires],
    );
    const botUsername =
      process.env.WEB_TELEGRAM_BOT_USERNAME?.replace(/^@/, '') ||
      'AmnesiaWebBot';
    const url = `https://t.me/${botUsername}?start=link_${token}`;
    return { ok: true as const, url, token, expiresAt: expires.toISOString() };
  }

  async completeTelegramLinkFromBot(
    token: string,
    telegramIdStr: string,
    telegramUsername?: string,
  ) {
    const cleanToken = String(token || '').replace(/^link_/, '');
    if (!cleanToken) {
      return { ok: false as const, error: 'invalid_token' };
    }
    const [tokRows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT user_id FROM telegram_link_tokens WHERE token = ? AND expires_at > NOW() LIMIT 1',
      [cleanToken],
    );
    if (!tokRows.length) {
      return { ok: false as const, error: 'expired_or_invalid' };
    }
    const userId = Number(tokRows[0].user_id);
    const tgId = String(telegramIdStr).replace(/\D/g, '');
    if (!tgId) {
      return { ok: false as const, error: 'bad_telegram_id' };
    }

    const [conflict] = await this.pool.execute<UserRow[]>(
      'SELECT id FROM users WHERE telegram_id = ? AND id <> ? LIMIT 1',
      [tgId, userId],
    );
    if (conflict.length) {
      await this.pool.execute(
        'DELETE FROM telegram_link_tokens WHERE token = ?',
        [cleanToken],
      );
      return { ok: false as const, error: 'telegram_already_linked' };
    }

    await this.pool.execute(
      'UPDATE users SET telegram_id = ?, telegram_username = ? WHERE id = ?',
      [tgId, telegramUsername || null, userId],
    );
    await this.pool.execute(
      'DELETE FROM telegram_link_tokens WHERE token = ?',
      [cleanToken],
    );
    return { ok: true as const };
  }
}
