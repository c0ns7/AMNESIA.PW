import { Global, Module } from '@nestjs/common';
import { createPool, Pool } from 'mysql2/promise';

export const MYSQL_POOL = 'MYSQL_POOL';
/** Вторая БД — та же, что у Telegram-бота (например amnesia_vpn), для баланса и remnawave_user_id */
export const VPN_DB_POOL = 'VPN_DB_POOL';

function createVpnPool(): Pool | null {
  const database =
    process.env.DB_NAME?.trim() || process.env.VPN_DATABASE?.trim() || '';
  if (!database) {
    return null;
  }
  return createPool({
    host: process.env.DB_HOST?.trim() || '127.0.0.1',
    port: Number(process.env.DB_PORT) || 3306,
    user: process.env.DB_USER?.trim() || 'root',
    password: process.env.DB_PASSWORD ?? '',
    database,
    waitForConnections: true,
    connectionLimit: 5,
    queueLimit: 0,
    connectTimeout: Number(process.env.MYSQL_CONNECT_TIMEOUT_MS) || 15000,
    enableKeepAlive: true,
  });
}

@Global()
@Module({
  providers: [
    {
      provide: MYSQL_POOL,
      useFactory: () =>
        createPool({
          host: process.env.MYSQL_HOST ?? '127.0.0.1',
          port: Number(process.env.MYSQL_PORT) || 3306,
          user: process.env.MYSQL_USER ?? 'root',
          password: process.env.MYSQL_PASSWORD ?? '',
          database: process.env.MYSQL_DATABASE ?? 'amnesia_pw',
          waitForConnections: true,
          connectionLimit: 10,
          queueLimit: 0,
          connectTimeout: Number(process.env.MYSQL_CONNECT_TIMEOUT_MS) || 15000,
          enableKeepAlive: true,
        }),
    },
    {
      provide: VPN_DB_POOL,
      useFactory: () => createVpnPool(),
    },
  ],
  exports: [MYSQL_POOL, VPN_DB_POOL],
})
export class DatabaseModule {}
