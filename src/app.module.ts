import {
  BadRequestException,
  Module,
  ValidationPipe,
} from '@nestjs/common';
import { APP_PIPE } from '@nestjs/core';
import { ThrottlerModule } from '@nestjs/throttler';
import { AppController } from './app.controller';
import { AuthModule } from './auth/auth.module';
import { DatabaseModule } from './database/database.module';
import { RemnawaveModule } from './remnawave/remnawave.module';
import { SubscriptionModule } from './subscription/subscription.module';
import { SiteAdminModule } from './site-admin/site-admin.module';
import { SiteController } from './site.controller';
import { getClientIp } from './utils/client-ip';
import { Request } from 'express';

@Module({
  imports: [
    ThrottlerModule.forRoot({
      throttlers: [
        {
          name: 'default',
          ttl: 60000,
          limit: 300,
        },
      ],
      getTracker: (req) => getClientIp(req as Request) || 'unknown',
    }),
    DatabaseModule,
    AuthModule,
    RemnawaveModule,
    SubscriptionModule,
    SiteAdminModule,
  ],
  controllers: [AppController, SiteController],
  providers: [
    {
      provide: APP_PIPE,
      useValue: new ValidationPipe({
        whitelist: true,
        transform: true,
        transformOptions: { enableImplicitConversion: true },
        exceptionFactory: (errors) => {
          const first = errors[0];
          const msg = first?.constraints
            ? String(Object.values(first.constraints)[0])
            : 'Проверьте поля формы';
          return new BadRequestException(msg);
        },
      }),
    },
  ],
})
export class AppModule {}
