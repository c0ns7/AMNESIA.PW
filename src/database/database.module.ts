import { Global, Module } from '@nestjs/common';
import { createPool } from 'mysql2/promise';

export const MYSQL_POOL = 'MYSQL_POOL';

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
  ],
  exports: [MYSQL_POOL],
})
export class DatabaseModule {}
