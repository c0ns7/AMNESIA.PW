import {
  BadRequestException,
  ConflictException,
  Inject,
  Injectable,
  NotFoundException,
  OnModuleInit,
  Optional,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import * as jwt from 'jsonwebtoken';
import { ResultSetHeader } from 'mysql2';
import { Pool, RowDataPacket } from 'mysql2/promise';
import { MYSQL_POOL, VPN_DB_POOL } from '../database/database.module';
import { RemnawaveService } from '../remnawave/remnawave.service';
import { SubscriptionLinkService } from '../subscription/subscription-link.service';
import { ActivatePromoDto } from './dto/activate-promo.dto';
import { RequestPasswordResetDto } from './dto/request-password-reset.dto';
import { CreateTopupDto } from './dto/create-topup.dto';
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
  telegram_login_otp_enabled?: number | boolean | null;
  trial_bonus_claimed?: number | boolean | null;
  telegram_link_bonus_claimed?: number | boolean | null;
}

interface AmnesiaJwtPayload {
  sub: number;
  u: string;
}

@Injectable()
export class AuthService implements OnModuleInit {
  constructor(
    @Inject(MYSQL_POOL) private readonly pool: Pool,
    @Optional() @Inject(VPN_DB_POOL) private readonly vpnPool: Pool | null,
    private readonly remnawaveService: RemnawaveService,
    private readonly subscriptionLinks: SubscriptionLinkService,
  ) {}

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
  private readonly plategaApiBase = (
    process.env.PLATEGA_API_BASE || 'https://app.platega.io'
  ).replace(/\/$/, '');
  private readonly plategaMerchantId =
    process.env.PLATEGA_MERCHANT_ID?.trim() || '';
  private readonly plategaSecret = process.env.PLATEGA_SECRET?.trim() || '';
  private readonly TOPUP_CARD_METHODS = [11, 10];
  private readonly TOPUP_SBP_METHOD = 2;
  private readonly WEB_BONUS_TRIAL_20 = 'trial_20_rub';
  private readonly WEB_BONUS_TELEGRAM_50 = 'telegram_link_50_rub';

  async onModuleInit() {
    this.ensureJwtSecretStrong();
    await this.ensureSchema();
    await this.ensureVpnUsersBillingColumn();
  }

  private ensureJwtSecretStrong(): void {
    const weak =
      !this.jwtSecret ||
      this.jwtSecret === 'change-me-in-production' ||
      this.jwtSecret.length < 32;
    if (process.env.NODE_ENV === 'production' && weak) {
      throw new Error(
        'JWT_SECRET (или SESSION_SECRET) должен быть задан и не короче 32 символов в production',
      );
    }
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
      version: 'v3' as const,
    };
  }

  getTelegramWidgetConfig() {
    const token = this.webTelegramBotToken;
    const disabled =
      process.env.WEB_TELEGRAM_WIDGET_ENABLED?.trim() === '0';
    const botUsername = (
      process.env.WEB_TELEGRAM_BOT_USERNAME?.trim() || 'AmnesiaWebBot'
    ).replace(/^@/, '');
    return {
      enabled: Boolean(token && !disabled),
      botUsername,
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
    try {
      await this.pool.execute(
        'ALTER TABLE users ADD COLUMN telegram_login_otp_enabled TINYINT(1) NOT NULL DEFAULT 0',
      );
    } catch (_) {
      /* exists */
    }
    try {
      await this.pool.execute(
        'ALTER TABLE users ADD COLUMN trial_bonus_claimed TINYINT(1) NOT NULL DEFAULT 0',
      );
    } catch (_) {
      /* exists */
    }
    try {
      await this.pool.execute(
        'ALTER TABLE users ADD COLUMN telegram_link_bonus_claimed TINYINT(1) NOT NULL DEFAULT 0',
      );
    } catch (_) {
      /* exists */
    }
    await this.pool.execute(`
      CREATE TABLE IF NOT EXISTS telegram_login_challenges (
        id VARCHAR(64) NOT NULL PRIMARY KEY,
        user_id INT NOT NULL,
        code_hash VARCHAR(255) NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_tlc_user (user_id),
        INDEX idx_tlc_exp (expires_at)
      )
    `);
    await this.pool.execute(`
      CREATE TABLE IF NOT EXISTS telegram_password_reset_challenges (
        id VARCHAR(64) NOT NULL PRIMARY KEY,
        user_id INT NOT NULL,
        code_hash VARCHAR(255) NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_tprc_user (user_id),
        INDEX idx_tprc_exp (expires_at)
      )
    `);
  }

  /** Колонка для ежедневного списания тарифа (общая с bot.amnesiavps.ru). */
  private async ensureVpnUsersBillingColumn() {
    if (!this.vpnPool) return;
    try {
      await this.vpnPool.execute(
        'ALTER TABLE users ADD COLUMN last_daily_tariff_date DATE NULL',
      );
    } catch {
      /* already exists */
    }
    await this.vpnPool.execute(`
      CREATE TABLE IF NOT EXISTS payments (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id BIGINT NOT NULL,
        amount DECIMAL(10,2) NOT NULL,
        bonus_percent DECIMAL(5,2) NOT NULL DEFAULT 0,
        bonus_amount DECIMAL(10,2) NOT NULL DEFAULT 0,
        final_amount DECIMAL(10,2) NOT NULL,
        invoice_id VARCHAR(64) NOT NULL,
        platega_transaction_id VARCHAR(64) NULL,
        status VARCHAR(32) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX (user_id),
        INDEX (invoice_id),
        INDEX (platega_transaction_id)
      )
    `);
    await this.vpnPool.execute(`
      CREATE TABLE IF NOT EXISTS web_bonus_claims (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id BIGINT NOT NULL,
        bonus_code VARCHAR(64) NOT NULL,
        amount DECIMAL(10,2) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uq_web_bonus_claim (user_id, bonus_code),
        INDEX idx_web_bonus_user (user_id)
      )
    `);
  }

  private calcTopupBonus(amount: number): number {
    if (amount >= 2000) return 7;
    if (amount >= 1000) return 5;
    if (amount >= 500) return 3;
    return 0;
  }

  private async loadWebBonusFlags(telegramId: string | number | null) {
    const flags = {
      trial20Claimed: false,
      telegram50Claimed: false,
    };
    if (!this.vpnPool || telegramId == null) return flags;
    try {
      const [rows] = await this.vpnPool.execute<RowDataPacket[]>(
        'SELECT bonus_code FROM web_bonus_claims WHERE user_id = ?',
        [Number(telegramId)],
      );
      for (const row of rows) {
        const code = String(row.bonus_code || '');
        if (code === this.WEB_BONUS_TRIAL_20) flags.trial20Claimed = true;
        if (code === this.WEB_BONUS_TELEGRAM_50) flags.telegram50Claimed = true;
      }
    } catch {
      /* ignore */
    }
    return flags;
  }

  private isPaymentStatusPaid(statusRaw: unknown): boolean {
    const status = String(statusRaw || '')
      .trim()
      .toUpperCase()
      .replace(/\s+/g, '_');
    return [
      'CONFIRMED',
      'PAID',
      'COMPLETED',
      'SUCCESS',
      'SUCCEEDED',
      'DONE',
      'SETTLED',
    ].includes(status);
  }

  private extractPlategaStatusPayload(data: Record<string, unknown>): unknown {
    const tx = data.transaction as Record<string, unknown> | undefined;
    if (tx && typeof tx === 'object') {
      return (
        tx.status ??
        tx.state ??
        (tx as { paymentStatus?: unknown }).paymentStatus
      );
    }
    return data.status ?? data.state ?? (data as { paymentStatus?: unknown }).paymentStatus;
  }

  private async plategaGetStatus(transactionId: string): Promise<'paid' | 'pending' | null> {
    if (!this.plategaMerchantId || !this.plategaSecret || !transactionId) {
      return null;
    }
    try {
      const resp = await fetch(
        `${this.plategaApiBase}/transaction/${encodeURIComponent(transactionId)}`,
        {
          method: 'GET',
          headers: {
            'X-MerchantId': this.plategaMerchantId,
            'X-Secret': this.plategaSecret,
          },
        },
      );
      const data = (await resp.json().catch(() => ({}))) as Record<
        string,
        unknown
      >;
      if (!resp.ok) return null;
      const raw = this.extractPlategaStatusPayload(data);
      return this.isPaymentStatusPaid(raw) ? 'paid' : 'pending';
    } catch {
      return null;
    }
  }

  private async markPaymentSuccess(
    conn: Pool,
    payment: RowDataPacket,
  ): Promise<boolean> {
    const [upd] = await conn.execute<ResultSetHeader>(
      'UPDATE payments SET status = ?, updated_at = NOW() WHERE id = ? AND status IN (?, ?)',
      ['success', payment.id, 'pending', 'created'],
    );
    if (!upd.affectedRows) return false;

    const userId = Number(payment.user_id);
    const credited = Number(payment.final_amount || 0);
    await conn.execute(
      `UPDATE users SET
         balance = IFNULL(balance, 0) + ?,
         last_daily_tariff_date = IF(IFNULL(balance, 0) <= 0, CURDATE(), last_daily_tariff_date)
       WHERE user_id = ?`,
      [credited, userId],
    );

    const [rows] = await conn.execute<RowDataPacket[]>(
      'SELECT balance, remnawave_user_id FROM users WHERE user_id = ? LIMIT 1',
      [userId],
    );
    const br = rows[0];
    const newBalance = Number(br?.balance ?? 0);
    const rwUuid = br?.remnawave_user_id
      ? String(br.remnawave_user_id)
      : null;
    await this.remnawaveService.tryEnableSubscriptionIfEligible(
      rwUuid,
      newBalance,
    );
    return true;
  }

  private async sendTelegramLoginCode(chatId: string, code: string): Promise<void> {
    if (!this.webTelegramBotToken) {
      throw new ServiceUnavailableException('Telegram-бот для сайта не настроен');
    }
    const text =
      `<tg-emoji emoji-id="5422439311196834318">💡</tg-emoji> <b>Код входа в личный кабинет:</b> <code>${code}</code>\n\n` +
      `Действителен 10 минут. Если это не вы — смените пароль.`;
    const url = `https://api.telegram.org/bot${encodeURIComponent(this.webTelegramBotToken)}/sendMessage`;
    const body = new URLSearchParams({
      chat_id: String(chatId),
      text,
      parse_mode: 'HTML',
    });
    let response;
    try {
      response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
      });
    } catch {
      throw new ServiceUnavailableException(
        'Не удалось связаться с Telegram. Попробуйте позже.',
      );
    }
    const data = (await response.json().catch(() => ({}))) as {
      ok?: boolean;
      description?: string;
    };
    if (!response.ok || !data.ok) {
      throw new ServiceUnavailableException(
        data.description || 'Не удалось отправить код в Telegram',
      );
    }
  }

  private async sendTelegramPasswordResetCode(
    chatId: string,
    code: string,
  ): Promise<void> {
    if (!this.webTelegramBotToken) {
      throw new ServiceUnavailableException('Telegram-бот для сайта не настроен');
    }
    const text =
      `<tg-emoji emoji-id="5422439311196834318">🔐</tg-emoji> <b>Код сброса пароля:</b> <code>${code}</code>\n\n` +
      `Действителен 10 минут. Если это не вы — просто проигнорируйте сообщение.`;
    const url = `https://api.telegram.org/bot${encodeURIComponent(this.webTelegramBotToken)}/sendMessage`;
    const body = new URLSearchParams({
      chat_id: String(chatId),
      text,
      parse_mode: 'HTML',
    });
    let response;
    try {
      response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
      });
    } catch {
      throw new ServiceUnavailableException(
        'Не удалось связаться с Telegram. Попробуйте позже.',
      );
    }
    const data = (await response.json().catch(() => ({}))) as {
      ok?: boolean;
      description?: string;
    };
    if (!response.ok || !data.ok) {
      throw new ServiceUnavailableException(
        data.description || 'Не удалось отправить код в Telegram',
      );
    }
  }

  createAuthToken(user: SessionUser): string {
    const payload: AmnesiaJwtPayload = { sub: user.id, u: user.username };
    return jwt.sign(payload, this.jwtSecret, {
      expiresIn: Math.floor(this.jwtExpiresMs / 1000),
      algorithm: 'HS256',
    });
  }

  private parseJwtPayload(raw: unknown): AmnesiaJwtPayload | null {
    if (!raw || typeof raw !== 'object') return null;
    const o = raw as Record<string, unknown>;
    const subRaw = o.sub;
    let id: number;
    if (typeof subRaw === 'number' && Number.isInteger(subRaw)) {
      id = subRaw;
    } else if (typeof subRaw === 'string' && /^\d+$/.test(subRaw)) {
      id = parseInt(subRaw, 10);
    } else {
      return null;
    }
    if (id < 1) return null;
    const u = o.u;
    if (typeof u !== 'string') return null;
    const username = this.normalizeUsername(u);
    if (!username) return null;
    return { sub: id, u: username };
  }

  verifyAuthToken(token: string): SessionUser | null {
    try {
      const raw = jwt.verify(token, this.jwtSecret, {
        algorithms: ['HS256'],
      });
      const decoded = this.parseJwtPayload(raw);
      if (!decoded) return null;
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
      'SELECT id, username, password_hash, telegram_id, telegram_login_otp_enabled FROM users WHERE username = ? LIMIT 1',
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
    const otpOn =
      Number(row.telegram_login_otp_enabled) === 1 &&
      row.telegram_id != null;
    if (otpOn) {
      await this.pool.execute(
        'DELETE FROM telegram_login_challenges WHERE user_id = ?',
        [row.id],
      );
      const code = String(crypto.randomInt(100000, 1000000));
      const codeHash = await bcrypt.hash(code, 10);
      const challengeId = crypto.randomBytes(32).toString('hex');
      const expires = new Date(Date.now() + 10 * 60 * 1000);
      await this.pool.execute(
        'INSERT INTO telegram_login_challenges (id, user_id, code_hash, expires_at) VALUES (?, ?, ?, ?)',
        [challengeId, row.id, codeHash, expires],
      );
      try {
        await this.sendTelegramLoginCode(String(row.telegram_id), code);
      } catch (e) {
        await this.pool.execute(
          'DELETE FROM telegram_login_challenges WHERE id = ?',
          [challengeId],
        );
        throw e;
      }
      return {
        ok: true as const,
        needsTelegramOtp: true as const,
        challengeId,
      };
    }
    const user: SessionUser = { id: row.id, username: row.username };
    const token = this.createAuthToken(user);
    return {
      ok: true as const,
      token,
      user,
    };
  }

  async completeTelegramLoginOtp(challengeId: string, code: string) {
    const cleanId = String(challengeId || '').trim();
    if (!cleanId) {
      throw new BadRequestException('Нет сессии входа');
    }
    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT user_id, code_hash, expires_at FROM telegram_login_challenges WHERE id = ? LIMIT 1',
      [cleanId],
    );
    const r = rows[0];
    if (!r) {
      throw new BadRequestException('Сессия входа недействительна. Войдите снова.');
    }
    if (new Date(String(r.expires_at)) < new Date()) {
      await this.pool.execute(
        'DELETE FROM telegram_login_challenges WHERE id = ?',
        [cleanId],
      );
      throw new BadRequestException('Код истёк. Войдите снова.');
    }
    const okCode = await bcrypt.compare(String(code).trim(), String(r.code_hash));
    if (!okCode) {
      throw new UnauthorizedException('Неверный код');
    }
    await this.pool.execute(
      'DELETE FROM telegram_login_challenges WHERE id = ?',
      [cleanId],
    );
    const userId = Number(r.user_id);
    const [users] = await this.pool.execute<UserRow[]>(
      'SELECT id, username FROM users WHERE id = ? LIMIT 1',
      [userId],
    );
    const u = users[0];
    if (!u) {
      throw new UnauthorizedException();
    }
    const user: SessionUser = { id: u.id, username: u.username };
    const token = this.createAuthToken(user);
    return { ok: true as const, token, user };
  }

  async requestPasswordReset(
    dto: RequestPasswordResetDto,
    remoteIp?: string,
  ) {
    await this.verifyCaptcha(dto.captchaToken, remoteIp, 'login');
    const username = this.normalizeUsername(dto.username);
    const [rows] = await this.pool.execute<UserRow[]>(
      'SELECT id, telegram_id FROM users WHERE username = ? LIMIT 1',
      [username],
    );
    const row = rows[0];
    if (!row || row.telegram_id == null) {
      throw new BadRequestException(
        'Сброс пароля доступен только для аккаунтов с привязанным Telegram.',
      );
    }
    await this.pool.execute(
      'DELETE FROM telegram_password_reset_challenges WHERE user_id = ?',
      [row.id],
    );
    const code = String(crypto.randomInt(100000, 1000000));
    const codeHash = await bcrypt.hash(code, 10);
    const challengeId = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 10 * 60 * 1000);
    await this.pool.execute(
      'INSERT INTO telegram_password_reset_challenges (id, user_id, code_hash, expires_at) VALUES (?, ?, ?, ?)',
      [challengeId, row.id, codeHash, expires],
    );
    try {
      await this.sendTelegramPasswordResetCode(String(row.telegram_id), code);
    } catch (e) {
      await this.pool.execute(
        'DELETE FROM telegram_password_reset_challenges WHERE id = ?',
        [challengeId],
      );
      throw e;
    }
    return {
      ok: true as const,
      challengeId,
      message: 'Код отправлен в Telegram.',
    };
  }

  async completePasswordReset(
    challengeId: string,
    code: string,
    newPassword: string,
    confirmPassword: string,
  ) {
    const cleanId = String(challengeId || '').trim();
    if (!cleanId) {
      throw new BadRequestException('Нет сессии сброса пароля');
    }
    if (newPassword !== confirmPassword) {
      throw new BadRequestException('Пароли не совпадают');
    }
    if (String(newPassword || '').length < 6) {
      throw new BadRequestException('Новый пароль: минимум 6 символов');
    }
    const [rows] = await this.pool.execute<RowDataPacket[]>(
      'SELECT user_id, code_hash, expires_at FROM telegram_password_reset_challenges WHERE id = ? LIMIT 1',
      [cleanId],
    );
    const r = rows[0];
    if (!r) {
      throw new BadRequestException(
        'Сессия сброса недействительна. Запросите код заново.',
      );
    }
    if (new Date(String(r.expires_at)) < new Date()) {
      await this.pool.execute(
        'DELETE FROM telegram_password_reset_challenges WHERE id = ?',
        [cleanId],
      );
      throw new BadRequestException('Код истёк. Запросите новый.');
    }
    const okCode = await bcrypt.compare(String(code).trim(), String(r.code_hash));
    if (!okCode) {
      throw new UnauthorizedException('Неверный код');
    }
    const hash = await bcrypt.hash(newPassword, 10);
    await this.pool.execute('UPDATE users SET password_hash = ? WHERE id = ?', [
      hash,
      Number(r.user_id),
    ]);
    await this.pool.execute(
      'DELETE FROM telegram_password_reset_challenges WHERE id = ?',
      [cleanId],
    );
    return {
      ok: true as const,
      message: 'Пароль успешно изменён. Теперь войдите с новым паролем.',
    };
  }

  async setTelegramLoginOtpEnabled(userId: number, enabled: boolean) {
    const [rows] = await this.pool.execute<UserRow[]>(
      'SELECT id, telegram_id FROM users WHERE id = ? LIMIT 1',
      [userId],
    );
    const row = rows[0];
    if (!row) {
      throw new UnauthorizedException();
    }
    if (row.telegram_id == null) {
      throw new BadRequestException('Сначала привяжите Telegram');
    }
    await this.pool.execute(
      'UPDATE users SET telegram_login_otp_enabled = ? WHERE id = ?',
      [enabled ? 1 : 0, userId],
    );
    return { ok: true as const, telegramLoginOtpEnabled: enabled };
  }

  /** Баланс из БД бота + детали Remnawave по remnawave_user_id (без HTTP к боту). */
  private async loadServiceProfileFromVpnDb(
    telegramId: string,
  ): Promise<Record<string, unknown> | null> {
    if (!this.vpnPool) {
      return null;
    }
    try {
      const [rows] = await this.vpnPool.execute<RowDataPacket[]>(
        'SELECT balance, remnawave_user_id FROM users WHERE user_id = ? LIMIT 1',
        [Number(telegramId)],
      );
      const row = rows[0];
      if (!row) {
        return null;
      }
      const balance = Number(row.balance ?? 0);
      const subscriptionActive = balance >= 7;
      const remnawaveUuid =
        row.remnawave_user_id != null
          ? String(row.remnawave_user_id)
          : null;

      let subscriptionUrl: string | null = null;
      let devices: Array<{ id: string; name: string }> = [];
      let devicesLimit: number | null = null;
      let usedTrafficBytes: number | null = null;
      let lifetimeUsedTrafficBytes: number | null = null;

      if (remnawaveUuid) {
        const rw =
          await this.remnawaveService.getLkUserRemnawaveDetails(
            remnawaveUuid,
          );
        if (rw) {
          subscriptionUrl = rw.subscription_url;
          devices = rw.devices;
          devicesLimit = rw.devices_limit;
          usedTrafficBytes = rw.used_traffic_bytes;
          lifetimeUsedTrafficBytes = rw.lifetime_used_traffic_bytes;
        }
      }

      const nodesCount = await this.remnawaveService.getLkNodesCount();

      const base: Record<string, unknown> = {
        balance,
        subscription_active: subscriptionActive,
        subscription_url: subscriptionUrl,
        devices,
        devices_limit: devicesLimit,
        nodes_count: nodesCount,
        used_traffic_bytes: usedTrafficBytes,
        lifetime_used_traffic_bytes: lifetimeUsedTrafficBytes,
      };
      return await this.subscriptionLinks.enrichServiceProfile(base);
    } catch {
      return null;
    }
  }

  async getMe(userId: number) {
    const [rows] = await this.pool.execute<UserRow[]>(
      `SELECT id, username, telegram_id, telegram_username, telegram_login_otp_enabled,
              trial_bonus_claimed, telegram_link_bonus_claimed
       FROM users WHERE id = ? LIMIT 1`,
      [userId],
    );
    const row = rows[0];
    if (!row) {
      throw new UnauthorizedException();
    }
    let serviceProfile: Record<string, unknown> | null = null;
    if (row.telegram_id != null) {
      serviceProfile = await this.loadServiceProfileFromVpnDb(
        String(row.telegram_id),
      );
    }
    const webBonusFlags = await this.loadWebBonusFlags(row.telegram_id);
    return {
      ok: true as const,
      user: {
        id: row.id,
        username: row.username,
        telegram: row.telegram_id != null
          ? {
              id: String(row.telegram_id),
              username: row.telegram_username || null,
              loginOtpEnabled: Number(row.telegram_login_otp_enabled) === 1,
            }
          : null,
        bonuses: {
          trial20Claimed:
            Number(row.trial_bonus_claimed) === 1 ||
            webBonusFlags.trial20Claimed,
          telegram50Claimed:
            Number(row.telegram_link_bonus_claimed) === 1 ||
            webBonusFlags.telegram50Claimed,
        },
        serviceProfile,
      },
    };
  }

  private async applyWebBonus(
    siteUserId: number,
    kind: 'trial20' | 'telegram50',
  ) {
    if (!this.vpnPool) {
      throw new ServiceUnavailableException(
        'Бонусы временно недоступны: не настроена база VPN.',
      );
    }

    const [userRows] = await this.pool.execute<UserRow[]>(
      `SELECT id, telegram_id, telegram_username, trial_bonus_claimed, telegram_link_bonus_claimed
       FROM users WHERE id = ? LIMIT 1`,
      [siteUserId],
    );
    const siteUser = userRows[0];
    if (!siteUser) throw new UnauthorizedException();
    if (siteUser.telegram_id == null) {
      throw new BadRequestException(
        'Привяжите Telegram в разделе «Интеграции», чтобы получить бонус на баланс VPN.',
      );
    }

    const isTrial = kind === 'trial20';
    const amount = isTrial ? 20 : 50;
    const tgNumeric = Number(siteUser.telegram_id);
    const vpnUsername = siteUser.telegram_username?.trim() || 'Unknown';
    const bonusCode = isTrial
      ? this.WEB_BONUS_TRIAL_20
      : this.WEB_BONUS_TELEGRAM_50;
    const alreadyClaimed = isTrial
      ? Number(siteUser.trial_bonus_claimed) === 1
      : Number(siteUser.telegram_link_bonus_claimed) === 1;

    if (alreadyClaimed) {
      throw new BadRequestException(
        isTrial
          ? 'Тестовый период уже был активирован.'
          : 'Бонус +50 ₽ уже был получен.',
      );
    }

    const conn = await this.vpnPool.getConnection();
    try {
      await conn.beginTransaction();
      const [existing] = await conn.execute<RowDataPacket[]>(
        'SELECT 1 FROM web_bonus_claims WHERE user_id = ? AND bonus_code = ? LIMIT 1 FOR UPDATE',
        [tgNumeric, bonusCode],
      );
      if (existing.length) {
        throw new BadRequestException(
          isTrial
            ? 'Тестовый период уже был активирован.'
            : 'Бонус +50 ₽ уже был получен.',
        );
      }
      await conn.execute(
        'INSERT INTO users (user_id, username) VALUES (?, ?) ON DUPLICATE KEY UPDATE username = VALUES(username)',
        [tgNumeric, vpnUsername],
      );
      await conn.execute(
        `UPDATE users SET
           balance = IFNULL(balance, 0) + ?,
           last_daily_tariff_date = IF(IFNULL(balance, 0) <= 0, CURDATE(), last_daily_tariff_date)
         WHERE user_id = ?`,
        [amount, tgNumeric],
      );
      await conn.execute(
        'INSERT INTO web_bonus_claims (user_id, bonus_code, amount) VALUES (?, ?, ?)',
        [tgNumeric, bonusCode, amount],
      );
      await conn.commit();
    } catch (e) {
      try {
        await conn.rollback();
      } catch {
        /* ignore */
      }
      if (e instanceof BadRequestException) throw e;
      const err = e as { code?: string };
      if (err.code === 'ER_DUP_ENTRY') {
        throw new BadRequestException(
          isTrial
            ? 'Тестовый период уже был активирован.'
            : 'Бонус +50 ₽ уже был получен.',
        );
      }
      throw new ServiceUnavailableException(
        'Не удалось начислить бонус. Попробуйте позже.',
      );
    } finally {
      conn.release();
    }

    await this.pool.execute(
      isTrial
        ? 'UPDATE users SET trial_bonus_claimed = 1 WHERE id = ?'
        : 'UPDATE users SET telegram_link_bonus_claimed = 1 WHERE id = ?',
      [siteUserId],
    );

    let newBalance = 0;
    let rwUuid: string | null = null;
    try {
      const [balRows] = await this.vpnPool.execute<RowDataPacket[]>(
        'SELECT balance, remnawave_user_id FROM users WHERE user_id = ? LIMIT 1',
        [tgNumeric],
      );
      const br = balRows[0];
      if (br) {
        newBalance = Number(br.balance ?? 0);
        rwUuid =
          br.remnawave_user_id != null ? String(br.remnawave_user_id) : null;
      }
    } catch {
      /* ignore */
    }
    await this.remnawaveService.tryEnableSubscriptionIfEligible(
      rwUuid,
      newBalance,
    );

    return {
      ok: true as const,
      creditedRub: amount,
      message: isTrial
        ? 'Тестовый период активирован. Зачислено 20 ₽.'
        : 'Бонус за привязку Telegram активирован. Зачислено 50 ₽.',
    };
  }

  async claimTrialBonus(siteUserId: number) {
    return this.applyWebBonus(siteUserId, 'trial20');
  }

  async claimTelegramLinkBonus(siteUserId: number) {
    return this.applyWebBonus(siteUserId, 'telegram50');
  }

  /**
   * Та же логика, что у бота (promo_codes / promo_activations / users.user_id = Telegram).
   */
  async activatePromo(siteUserId: number, dto: ActivatePromoDto) {
    if (!this.vpnPool) {
      throw new ServiceUnavailableException(
        'Промокоды недоступны: не настроена база VPN (VPN_DATABASE / DB_NAME).',
      );
    }
    const rawCode = String(dto.code || '').trim();
    if (!rawCode) {
      throw new BadRequestException('Введите промокод');
    }
    const normalized = rawCode.toLowerCase();

    const [userRows] = await this.pool.execute<UserRow[]>(
      'SELECT id, telegram_id, telegram_username FROM users WHERE id = ? LIMIT 1',
      [siteUserId],
    );
    const siteUser = userRows[0];
    if (!siteUser) {
      throw new UnauthorizedException();
    }
    if (siteUser.telegram_id == null) {
      throw new BadRequestException(
        'Привяжите Telegram в разделе «Интеграции». Промокод зачисляет баланс на аккаунт VPN, привязанный к Telegram.',
      );
    }
    const tgNumeric = Number(siteUser.telegram_id);
    const vpnUsername = siteUser.telegram_username?.trim() || 'Unknown';

    interface PromoCodeRow extends RowDataPacket {
      id: number;
      activations_max: number;
      activations_used: number;
      balance_amount: string | number;
    }

    const conn = await this.vpnPool.getConnection();
    let amountCredited = 0;
    try {
      await conn.beginTransaction();
      const [promoRows] = await conn.execute<PromoCodeRow[]>(
        'SELECT id, activations_max, activations_used, balance_amount FROM promo_codes WHERE LOWER(code) = ? FOR UPDATE',
        [normalized],
      );
      const promo = promoRows[0];
      if (!promo) {
        await conn.rollback();
        throw new BadRequestException('Промокод не найден.');
      }
      if (promo.activations_used >= promo.activations_max) {
        await conn.rollback();
        throw new BadRequestException('Лимит активаций промокода исчерпан.');
      }
      const [existing] = await conn.execute<RowDataPacket[]>(
        'SELECT 1 FROM promo_activations WHERE promo_id = ? AND user_id = ? LIMIT 1',
        [promo.id, tgNumeric],
      );
      if (existing.length) {
        await conn.rollback();
        throw new BadRequestException('Вы уже активировали этот промокод.');
      }
      const amount = Number(promo.balance_amount);
      if (!(amount > 0)) {
        await conn.rollback();
        throw new BadRequestException('Промокод недействителен.');
      }

      await conn.execute(
        'INSERT INTO users (user_id, username) VALUES (?, ?) ON DUPLICATE KEY UPDATE username = VALUES(username)',
        [tgNumeric, vpnUsername],
      );
      await conn.execute(
        'INSERT INTO promo_activations (promo_id, user_id) VALUES (?, ?)',
        [promo.id, tgNumeric],
      );
      await conn.execute(
        'UPDATE promo_codes SET activations_used = activations_used + 1 WHERE id = ?',
        [promo.id],
      );
      await conn.execute(
        `UPDATE users SET
           balance = IFNULL(balance, 0) + ?,
           last_daily_tariff_date = IF(IFNULL(balance, 0) <= 0, CURDATE(), last_daily_tariff_date)
         WHERE user_id = ?`,
        [amount, tgNumeric],
      );
      await conn.commit();
      amountCredited = amount;
    } catch (e) {
      try {
        await conn.rollback();
      } catch {
        /* already rolled back or no tx */
      }
      if (
        e instanceof BadRequestException ||
        e instanceof UnauthorizedException
      ) {
        throw e;
      }
      const err = e as { code?: string };
      if (err.code === 'ER_DUP_ENTRY') {
        throw new BadRequestException('Вы уже активировали этот промокод.');
      }
      throw new ServiceUnavailableException(
        'Не удалось применить промокод. Попробуйте позже.',
      );
    } finally {
      conn.release();
    }

    let newBalance = 0;
    let rwUuid: string | null = null;
    try {
      const [balRows] = await this.vpnPool.execute<RowDataPacket[]>(
        'SELECT balance, remnawave_user_id FROM users WHERE user_id = ? LIMIT 1',
        [tgNumeric],
      );
      const br = balRows[0];
      if (br) {
        newBalance = Number(br.balance ?? 0);
        rwUuid =
          br.remnawave_user_id != null
            ? String(br.remnawave_user_id)
            : null;
      }
    } catch {
      /* ignore */
    }
    await this.remnawaveService.tryEnableSubscriptionIfEligible(
      rwUuid,
      newBalance,
    );

    const creditedRub = Math.round(amountCredited * 100) / 100;
    return {
      ok: true as const,
      creditedRub,
      message: `Промокод активирован. Зачислено ${creditedRub.toFixed(2)} ₽.`,
    };
  }

  async createTopup(siteUserId: number, dto: CreateTopupDto) {
    if (!this.vpnPool) {
      throw new ServiceUnavailableException(
        'Платежи недоступны: не настроена база VPN.',
      );
    }
    if (!this.plategaMerchantId || !this.plategaSecret) {
      throw new ServiceUnavailableException(
        'Платежи временно недоступны: Platega не настроена.',
      );
    }

    const [userRows] = await this.pool.execute<UserRow[]>(
      'SELECT id, telegram_id, telegram_username FROM users WHERE id = ? LIMIT 1',
      [siteUserId],
    );
    const siteUser = userRows[0];
    if (!siteUser) throw new UnauthorizedException();
    if (siteUser.telegram_id == null) {
      throw new BadRequestException(
        'Привяжите Telegram в разделе «Интеграции», чтобы пополнять баланс VPN.',
      );
    }

    const tgNumeric = Number(siteUser.telegram_id);
    const vpnUsername = siteUser.telegram_username?.trim() || 'Unknown';
    const amount = Math.round(Number(dto.amount || 0) * 100) / 100;
    if (!Number.isFinite(amount) || amount < 10) {
      throw new BadRequestException('Минимальная сумма пополнения — 10 ₽.');
    }

    const bonusPercent = this.calcTopupBonus(amount);
    const bonusAmount = Math.round((amount * bonusPercent) / 100 * 100) / 100;
    const finalAmount = Math.round((amount + bonusAmount) * 100) / 100;
    const invoiceId = crypto.randomUUID();

    await this.vpnPool.execute(
      'INSERT INTO users (user_id, username) VALUES (?, ?) ON DUPLICATE KEY UPDATE username = VALUES(username)',
      [tgNumeric, vpnUsername],
    );
    const [ins] = await this.vpnPool.execute<ResultSetHeader>(
      `INSERT INTO payments
        (user_id, amount, bonus_percent, bonus_amount, final_amount, invoice_id, status)
       VALUES (?, ?, ?, ?, ?, ?, 'pending')`,
      [tgNumeric, amount, bonusPercent, bonusAmount, finalAmount, invoiceId],
    );
    const paymentId = ins.insertId;

    const methods =
      dto.method === 'sbp'
        ? [this.TOPUP_SBP_METHOD]
        : this.TOPUP_CARD_METHODS.slice();

    let lastStatus: number | string | null = null;
    let redirectUrl: string | null = null;
    let transactionId: string | null = null;

    for (const methodId of methods) {
      let resp: Response;
      try {
        resp = await fetch(`${this.plategaApiBase}/transaction/process`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-MerchantId': this.plategaMerchantId,
            'X-Secret': this.plategaSecret,
          },
          body: JSON.stringify({
            paymentMethod: methodId,
            paymentDetails: { amount, currency: 'RUB' },
            description: 'Пополнение баланса AMNESIA VPN (LK)',
            payload: invoiceId,
          }),
        });
      } catch {
        lastStatus = 'network_error';
        continue;
      }
      const data = (await resp.json().catch(() => ({}))) as Record<
        string,
        unknown
      >;
      lastStatus = resp.status;
      if (![200, 201].includes(resp.status)) continue;

      const txRaw = data.transactionId || data.transaction_id || data.id;
      if (txRaw != null) {
        transactionId = String(txRaw);
      }
      const pd = (data.paymentDetails || {}) as Record<string, unknown>;
      const direct =
        data.redirect ||
        data.payment_url ||
        data.paymentUrl ||
        data.url ||
        data.link;
      const nested = pd.url || pd.redirect;
      const urlRaw = direct || nested;
      if (typeof urlRaw === 'string' && urlRaw.trim()) {
        redirectUrl = urlRaw.trim();
      }
      if (transactionId || redirectUrl) {
        break;
      }
    }

    if (transactionId) {
      await this.vpnPool.execute(
        'UPDATE payments SET platega_transaction_id = ?, status = ? WHERE id = ?',
        [transactionId, 'created', paymentId],
      );
    }
    if (!redirectUrl) {
      await this.vpnPool.execute(
        'UPDATE payments SET status = ? WHERE id = ?',
        ['error', paymentId],
      );
      throw new ServiceUnavailableException(
        `Не удалось создать платёж (Platega status: ${String(lastStatus)}).`,
      );
    }

    return {
      ok: true as const,
      paymentId,
      invoiceId,
      amount,
      bonusPercent,
      bonusAmount,
      finalAmount,
      status: 'created' as const,
      paymentUrl: redirectUrl,
    };
  }

  async checkTopup(siteUserId: number, paymentId: number) {
    if (!this.vpnPool) {
      throw new ServiceUnavailableException(
        'Платежи недоступны: не настроена база VPN.',
      );
    }
    const [userRows] = await this.pool.execute<UserRow[]>(
      'SELECT id, telegram_id FROM users WHERE id = ? LIMIT 1',
      [siteUserId],
    );
    const siteUser = userRows[0];
    if (!siteUser) throw new UnauthorizedException();
    if (siteUser.telegram_id == null) {
      throw new BadRequestException('Привяжите Telegram.');
    }

    const tgNumeric = Number(siteUser.telegram_id);
    const [rows] = await this.vpnPool.execute<RowDataPacket[]>(
      'SELECT * FROM payments WHERE id = ? AND user_id = ? LIMIT 1',
      [paymentId, tgNumeric],
    );
    const payment = rows[0];
    if (!payment) {
      throw new NotFoundException('Платёж не найден.');
    }
    if (String(payment.status) === 'success') {
      return { ok: true as const, status: 'success' as const, credited: true };
    }

    const txId = payment.platega_transaction_id
      ? String(payment.platega_transaction_id)
      : '';
    if (!txId) {
      return {
        ok: true as const,
        status: String(payment.status || 'pending'),
        credited: false,
      };
    }

    const plategaStatus = await this.plategaGetStatus(txId);
    if (plategaStatus !== 'paid') {
      return {
        ok: true as const,
        status: String(payment.status || 'pending'),
        credited: false,
      };
    }
    const credited = await this.markPaymentSuccess(this.vpnPool, payment);
    return { ok: true as const, status: 'success' as const, credited };
  }

  /** Список платежей VPN для текущего пользователя ЛК (по Telegram ID). */
  async listPayments(siteUserId: number, limitRaw = 50) {
    if (!this.vpnPool) {
      throw new ServiceUnavailableException(
        'Платежи недоступны: не настроена база VPN.',
      );
    }
    const [userRows] = await this.pool.execute<UserRow[]>(
      'SELECT id, telegram_id FROM users WHERE id = ? LIMIT 1',
      [siteUserId],
    );
    const siteUser = userRows[0];
    if (!siteUser) throw new UnauthorizedException();
    if (siteUser.telegram_id == null) {
      throw new BadRequestException('Привяжите Telegram.');
    }
    const tgNumeric = Number(siteUser.telegram_id);
    const limit = Math.min(100, Math.max(1, Math.floor(Number(limitRaw) || 50)));

    interface PayRow extends RowDataPacket {
      id: number;
      amount: string | number;
      bonus_percent: string | number | null;
      bonus_amount: string | number | null;
      final_amount: string | number | null;
      invoice_id: string | null;
      status: string | null;
      created_at: Date | string | null;
      updated_at: Date | string | null;
    }

    const [rows] = await this.vpnPool.execute<PayRow[]>(
      `SELECT id, amount, bonus_percent, bonus_amount, final_amount, invoice_id, status,
              created_at, updated_at
       FROM payments
       WHERE user_id = ?
       ORDER BY id DESC
       LIMIT ?`,
      [tgNumeric, limit],
    );

    const tabFor = (s: string): 'success' | 'processing' | 'failed' => {
      const u = s.toLowerCase();
      if (u === 'success') return 'success';
      if (u === 'pending' || u === 'created') return 'processing';
      return 'failed';
    };

    const payments = rows.map((r) => {
      const st = String(r.status || 'pending');
      return {
        id: r.id,
        amount: Number(r.amount ?? 0),
        bonusPercent: r.bonus_percent != null ? Number(r.bonus_percent) : null,
        bonusAmount: r.bonus_amount != null ? Number(r.bonus_amount) : null,
        finalAmount: r.final_amount != null ? Number(r.final_amount) : null,
        invoiceId: r.invoice_id ? String(r.invoice_id) : null,
        status: st,
        tab: tabFor(st),
        createdAt: r.created_at
          ? new Date(r.created_at as Date).toISOString()
          : null,
        updatedAt: r.updated_at
          ? new Date(r.updated_at as Date).toISOString()
          : null,
      };
    });

    return { ok: true as const, payments };
  }

  async processPlategaWebhook(payload: unknown) {
    if (!this.vpnPool) return { ok: true as const };
    const body = (payload || {}) as Record<string, unknown>;
    const tx = (body.transaction || {}) as Record<string, unknown>;
    const statusRaw = tx.status || body.status;
    const status = String(statusRaw || '').toLowerCase();
    const invoiceId =
      tx.invoiceId || tx.invoice_id || tx.id || body.invoiceId || body.invoice_id;
    if (!invoiceId) return { ok: true as const };

    const [rows] = await this.vpnPool.execute<RowDataPacket[]>(
      'SELECT * FROM payments WHERE invoice_id = ? LIMIT 1',
      [String(invoiceId)],
    );
    const payment = rows[0];
    if (!payment) return { ok: true as const };
    if (String(payment.status) === 'success') return { ok: true as const };

    if (!['success', 'paid', 'completed'].includes(status)) {
      await this.vpnPool.execute(
        'UPDATE payments SET status = ?, updated_at = NOW() WHERE id = ? AND status IN (?, ?)',
        [status || 'failed', payment.id, 'pending', 'created'],
      );
      return { ok: true as const };
    }

    const txId = tx.id || body.transactionId || body.transaction_id || null;
    if (txId != null) {
      await this.vpnPool.execute(
        'UPDATE payments SET platega_transaction_id = ? WHERE id = ?',
        [String(txId), payment.id],
      );
      payment.platega_transaction_id = String(txId);
    }

    await this.markPaymentSuccess(this.vpnPool, payment);
    return { ok: true as const };
  }

  /** Удаление HWID-устройства в Remnawave (как miniapp device-delete в боте). */
  async removeSubscriptionDevice(siteUserId: number, hwid: string) {
    const clean = String(hwid || '').trim();
    if (!clean) {
      throw new BadRequestException('Не указано устройство');
    }
    const [userRows] = await this.pool.execute<UserRow[]>(
      'SELECT id, telegram_id FROM users WHERE id = ? LIMIT 1',
      [siteUserId],
    );
    const siteUser = userRows[0];
    if (!siteUser) {
      throw new UnauthorizedException();
    }
    if (siteUser.telegram_id == null) {
      throw new BadRequestException('Привяжите Telegram');
    }
    if (!this.vpnPool) {
      throw new ServiceUnavailableException(
        'Сервис временно недоступен (нет VPN_DATABASE).',
      );
    }
    const [vpnRows] = await this.vpnPool.execute<RowDataPacket[]>(
      'SELECT remnawave_user_id FROM users WHERE user_id = ? LIMIT 1',
      [Number(siteUser.telegram_id)],
    );
    const rwUuid = vpnRows[0]?.remnawave_user_id;
    if (rwUuid == null || String(rwUuid).trim() === '') {
      throw new BadRequestException('Подписка ещё не создана в Remnawave');
    }
    const ok = await this.remnawaveService.deleteHwidDevice(
      String(rwUuid),
      clean,
    );
    if (!ok) {
      throw new ServiceUnavailableException(
        'Не удалось удалить устройство. Попробуйте позже.',
      );
    }
    return { ok: true as const };
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

  async unlinkTelegram(userId: number) {
    const [rows] = await this.pool.execute<UserRow[]>(
      'SELECT id FROM users WHERE id = ? LIMIT 1',
      [userId],
    );
    if (!rows[0]) {
      throw new UnauthorizedException();
    }
    await this.pool.execute(
      'UPDATE users SET telegram_id = NULL, telegram_username = NULL, telegram_login_otp_enabled = 0 WHERE id = ?',
      [userId],
    );
    return { ok: true as const };
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
