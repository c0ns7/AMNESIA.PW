import {
  BadRequestException,
  ConflictException,
  Inject,
  Injectable,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { Pool, RowDataPacket } from 'mysql2/promise';
import { MYSQL_POOL } from '../database/database.module';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';

interface UserRow extends RowDataPacket {
  id: number;
  username: string;
  password_hash: string;
}

@Injectable()
export class AuthService {
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
  private readonly recaptchaMinScore = Number(process.env.RECAPTCHA_MIN_SCORE || 0.5);

  private normalizeUsername(raw: string): string {
    return raw.trim().toLowerCase();
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
    return { siteKey: this.recaptchaSiteKey, version: 'v3', minScore: this.recaptchaMinScore };
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

      // Common Google error codes:
      // - invalid-input-secret: bad secret key (server side)
      // - missing-input-secret: secret not provided
      // - invalid-input-response: token invalid/expired (client side)
      // - missing-input-response: token missing
      if (codeSet.has('invalid-input-secret') || codeSet.has('missing-input-secret')) {
        throw new ServiceUnavailableException('Капча настроена неверно (secret key)');
      }
      if (codeSet.has('invalid-input-response') || codeSet.has('missing-input-response')) {
        throw new BadRequestException(
          'Подтвердите, что вы не робот' + (codes.length ? ` (${codes.join(', ')})` : ''),
        );
      }
      if (codeSet.has('timeout-or-duplicate')) {
        throw new BadRequestException('Подтвердите, что вы не робот (token expired)');
      }

      throw new BadRequestException(
        'Проверка капчи не пройдена' + (codes.length ? ` (${codes.join(', ')})` : ''),
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
    await this.pool.execute(
      'INSERT INTO users (username, password_hash) VALUES (?, ?)',
      [username, passwordHash],
    );
    return { ok: true as const, message: 'Регистрация успешна' };
  }

  async login(dto: LoginDto, remoteIp?: string) {
    await this.verifyCaptcha(dto.captchaToken, remoteIp, 'login');
    const username = this.normalizeUsername(dto.username);
    const [rows] = await this.pool.execute<UserRow[]>(
      'SELECT id, username, password_hash FROM users WHERE username = ? LIMIT 1',
      [username],
    );
    const user = rows[0];
    if (!user) {
      throw new UnauthorizedException('Неверный логин или пароль');
    }
    const match = await bcrypt.compare(dto.password, user.password_hash);
    if (!match) {
      throw new UnauthorizedException('Неверный логин или пароль');
    }
    return {
      ok: true as const,
      user: { id: user.id, username: user.username },
    };
  }
}
