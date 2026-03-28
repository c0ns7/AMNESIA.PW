import * as dotenv from 'dotenv';
import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import * as cookieParser from 'cookie-parser';
import { NextFunction, Request, Response } from 'express';
import { join } from 'path';
import { AppModule } from './app.module';
import { AllExceptionsFilter } from './filters/all-exceptions.filter';

// Make env loading robust for systemd (cwd may differ).
dotenv.config({ path: join(process.cwd(), '.env') });
dotenv.config({ path: join(__dirname, '..', '.env') });
dotenv.config();

const publicRoot = join(__dirname, '..', 'public');

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  // За nginx / TLS-терминацией — иначе req.ip / secure-куки ведут себя непредсказуемо.
  if (
    process.env.TRUST_PROXY === '1' ||
    process.env.NODE_ENV === 'production'
  ) {
    app.set('trust proxy', 1);
  }
  app.useGlobalFilters(new AllExceptionsFilter());
  app.use(cookieParser());

  // Явно до static: без public/lk/index.html после git pull static «молчит» → срабатывал catch-all 404 ниже.
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (req.method !== 'GET') {
      return next();
    }
    const pathOnly = (req.path || '').split('?')[0];
    const fromOriginal = (req.originalUrl || '').split('?')[0];
    if (
      pathOnly === '/lk' ||
      pathOnly === '/lk/' ||
      fromOriginal === '/lk' ||
      fromOriginal === '/lk/'
    ) {
      return res.sendFile(join(publicRoot, 'lk', 'index.html'), (err) => {
        if (err) {
          next(err);
        }
      });
    }
    const isLogin =
      pathOnly === '/login' ||
      pathOnly === '/login/' ||
      fromOriginal === '/login' ||
      fromOriginal === '/login/';
    if (isLogin) {
      return res.redirect(302, '/lk');
    }
    return next();
  });

  app.useStaticAssets(publicRoot, {
    index: ['index.html'],
    fallthrough: true,
  });

  // Только если ответ ещё не отправлен (иначе затирали HTML-страницы из SiteController).
  app.use((req: Request, res: Response, next: NextFunction) => {
    if (req.path.startsWith('/api')) {
      return next();
    }
    if (res.headersSent) {
      return next();
    }
    return res.status(404).sendFile(join(publicRoot, '404.html'));
  });

  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
