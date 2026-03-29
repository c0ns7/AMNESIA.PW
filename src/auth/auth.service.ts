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
      'SELECT id, username, telegram_id, telegram_username, telegram_login_otp_enabled FROM users WHERE id = ? LIMIT 1',
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
        serviceProfile,
      },
    };
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
        'UPDATE users SET balance = IFNULL(balance, 0) + ? WHERE user_id = ?',
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
