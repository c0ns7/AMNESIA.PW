import {
  BadRequestException,
  ConflictException,
  Inject,
  Injectable,
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

  private normalizeUsername(raw: string): string {
    return raw.trim().toLowerCase();
  }

  async register(dto: RegisterDto) {
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

  async login(dto: LoginDto) {
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
