import {
  Body,
  Controller,
  Headers,
  Post,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { InternalTelegramLinkDto } from './dto/internal-telegram-link.dto';

@Controller('api/internal')
export class InternalController {
  constructor(private readonly auth: AuthService) {}

  @Post('telegram-link')
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
