import {
  Body,
  Controller,
  Get,
  Post,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { AuthSessionGuard, RequestWithSession } from './auth-session.guard';
import { ChangePasswordDto } from './dto/change-password.dto';
import { LoginTelegramOtpDto } from './dto/login-telegram-otp.dto';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { TelegramLoginOtpPrefDto } from './dto/telegram-login-otp-pref.dto';
import { TelegramWidgetDto } from './dto/telegram-widget.dto';

@Controller('api/auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  private setCookie(res: Response, token: string) {
    res.cookie(this.auth.getCookieName(), token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: this.auth.getJwtMaxAgeMs(),
      path: '/',
    });
  }

  private clearCookie(res: Response) {
    res.clearCookie(this.auth.getCookieName(), { path: '/' });
  }

  @Get('captcha-config')
  captchaConfig() {
    return this.auth.getCaptchaConfig();
  }

  @Get('telegram-widget-config')
  telegramWidgetConfig() {
    return this.auth.getTelegramWidgetConfig();
  }

  @Post('register')
  async register(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Body() body: RegisterDto,
  ) {
    const result = await this.auth.register(body, req.ip);
    this.setCookie(res, result.token);
    return { ok: true, message: result.message, user: result.user };
  }

  @Post('login')
  async login(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Body() body: LoginDto,
  ) {
    const result = await this.auth.login(body, req.ip);
    if ('needsTelegramOtp' in result && result.needsTelegramOtp) {
      return {
        ok: true,
        needsTelegramOtp: true,
        challengeId: result.challengeId,
      };
    }
    this.setCookie(res, result.token);
    return { ok: true, user: result.user };
  }

  @Post('login/telegram-otp')
  async loginTelegramOtp(
    @Res({ passthrough: true }) res: Response,
    @Body() body: LoginTelegramOtpDto,
  ) {
    const result = await this.auth.completeTelegramLoginOtp(
      body.challengeId,
      body.code,
    );
    this.setCookie(res, result.token);
    return { ok: true, user: result.user };
  }

  @Post('logout')
  logout(@Res({ passthrough: true }) res: Response) {
    this.clearCookie(res);
    return { ok: true as const };
  }

  @Get('me')
  @UseGuards(AuthSessionGuard)
  async me(@Req() req: RequestWithSession) {
    const u = req.sessionUser;
    if (!u) throw new UnauthorizedException();
    return this.auth.getMe(u.id);
  }

  @Post('password')
  @UseGuards(AuthSessionGuard)
  async password(
    @Req() req: RequestWithSession,
    @Body() body: ChangePasswordDto,
  ) {
    const u = req.sessionUser;
    if (!u) throw new UnauthorizedException();
    return this.auth.changePassword(
      u.id,
      body.currentPassword,
      body.newPassword,
      body.confirmPassword,
    );
  }

  /** Telegram Login Widget (same-origin callback) */
  @Post('telegram/widget')
  async telegramWidget(
    @Res({ passthrough: true }) res: Response,
    @Body() body: TelegramWidgetDto,
  ) {
    const result = await this.auth.loginWithTelegramWidget(body);
    this.setCookie(res, result.token);
    return { ok: true, user: result.user };
  }

  @Post('telegram/link-start')
  @UseGuards(AuthSessionGuard)
  async telegramLinkStart(@Req() req: RequestWithSession) {
    const u = req.sessionUser;
    if (!u) throw new UnauthorizedException();
    return this.auth.startTelegramLink(u.id);
  }

  @Post('telegram/unlink')
  @UseGuards(AuthSessionGuard)
  async telegramUnlink(@Req() req: RequestWithSession) {
    const u = req.sessionUser;
    if (!u) throw new UnauthorizedException();
    return this.auth.unlinkTelegram(u.id);
  }

  @Post('telegram/login-otp-enabled')
  @UseGuards(AuthSessionGuard)
  async telegramLoginOtpPref(
    @Req() req: RequestWithSession,
    @Body() body: TelegramLoginOtpPrefDto,
  ) {
    const u = req.sessionUser;
    if (!u) throw new UnauthorizedException();
    return this.auth.setTelegramLoginOtpEnabled(u.id, body.enabled);
  }
}
