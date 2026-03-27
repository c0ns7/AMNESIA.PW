import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { Response } from 'express';

type Err = Error & { code?: string; errno?: number; sqlMessage?: string };

function mapMysqlOrNetworkError(err: Err): string | null {
  const c = err.code;
  const msg = err.message ?? '';

  if (c === 'ECONNREFUSED') {
    return 'Не удалось подключиться к базе данных. Проверьте, что MySQL/MariaDB запущен и в .env указаны верные MYSQL_HOST и MYSQL_PORT.';
  }
  if (c === 'ETIMEDOUT') {
    return 'Таймаут подключения к базе данных. Проверьте сеть и firewall.';
  }
  if (
    c === 'PROTOCOL_CONNECTION_LOST' ||
    c === 'EPIPE' ||
    msg.includes('Connection lost') ||
    msg.includes('server closed the connection')
  ) {
    return 'Соединение с базой данных разорвано. Если БД на другом сервере: создайте пользователя вида user@\'%\' (или с вашим IP), откройте порт 3306 и настройте bind-address в MariaDB; либо используйте SSH-туннель.';
  }
  if (c === 'ER_ACCESS_DENIED_ERROR' || err.errno === 1045) {
    return 'Доступ к базе данных отклонён: неверный MYSQL_USER или MYSQL_PASSWORD.';
  }
  if (c === 'ER_BAD_DB_ERROR' || err.errno === 1049) {
    return 'База данных не найдена. Проверьте MYSQL_DATABASE в .env (например amnesia_web).';
  }
  if (c === 'ENOTFOUND') {
    return 'Не удалось разрешить имя хоста базы данных (MYSQL_HOST).';
  }
  return null;
}

function normalizeHttpMessage(raw: string | string[] | object): string {
  if (Array.isArray(raw)) {
    const first = raw[0];
    return typeof first === 'string' ? first : 'Ошибка запроса';
  }
  if (typeof raw === 'string') {
    if (raw === 'Internal Server Error') {
      return 'Внутренняя ошибка сервера';
    }
    return raw;
  }
  if (raw && typeof raw === 'object' && 'message' in raw) {
    const m = (raw as { message?: string | string[] }).message;
    if (Array.isArray(m)) return typeof m[0] === 'string' ? m[0] : 'Ошибка запроса';
    if (typeof m === 'string') return m;
  }
  return 'Ошибка запроса';
}

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const res = ctx.getResponse<Response>();
    if (exception instanceof HttpException) {
      const status = exception.getStatus();
      const body = exception.getResponse();
      let message: string;

      if (typeof body === 'string') {
        message = normalizeHttpMessage(body);
      } else if (body && typeof body === 'object') {
        const b = body as { message?: string | string[]; error?: string };
        if (Array.isArray(b.message)) {
          message = String(b.message[0] ?? 'Ошибка запроса');
        } else if (typeof b.message === 'string') {
          message = normalizeHttpMessage(b.message);
        } else {
          message = exception.message || 'Ошибка запроса';
        }
      } else {
        message = exception.message || 'Ошибка запроса';
      }

      if (message === 'Internal Server Error') {
        message = 'Внутренняя ошибка сервера';
      }

      return res.status(status).json({
        statusCode: status,
        message,
      });
    }

    const err = exception as Err;
    const mapped = mapMysqlOrNetworkError(err);
    const status = HttpStatus.INTERNAL_SERVER_ERROR;
    const message = mapped ?? 'Внутренняя ошибка сервера. Попробуйте позже.';

    return res.status(status).json({
      statusCode: status,
      message,
    });
  }
}
