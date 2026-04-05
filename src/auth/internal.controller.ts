import {
  Body,
  Controller,
  Headers,
  Post,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { Throttle, ThrottlerGuard } from '@nestjs/throttler';
import { AuthService } from './auth.service';
import { InternalTelegramLinkDto } from './dto/internal-telegram-link.dto';

@Controller('api/internal')
export class InternalController {
  constructor(private readonly auth: AuthService) {}

  @Post('telegram-link')
  @UseGuards(ThrottlerGuard)
  @Throttle({ default: { limit: 60, ttl: 60000 } })
  async telegramLink(
    @Headers('x-web-bot-secret') secret: string,
    @Body() body: InternalTelegramLinkDto,
  ) {
    const expected = process.env.WEB_BOT_INTERNAL_SECRET?.trim();
    if (!expected || secret !== expected) {
      throw new UnauthorizedException();
    }
    return this.auth.completeTelegramLinkFromBot(
      body.token,
      body.telegramId,
      body.telegramUsername,
    );
  }
}
