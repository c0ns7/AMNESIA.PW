import {
  BadRequestException,
  Module,
  ValidationPipe,
} from '@nestjs/common';
import { APP_PIPE } from '@nestjs/core';
import { AppController } from './app.controller';
import { AuthModule } from './auth/auth.module';
import { DatabaseModule } from './database/database.module';
import { SiteController } from './site.controller';

@Module({
  imports: [DatabaseModule, AuthModule],
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
