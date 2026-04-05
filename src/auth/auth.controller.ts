import {
  Body,
  Controller,
  Get,
  Post,
  Query,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { Throttle, ThrottlerGuard } from '@nestjs/throttler';
import { Request, Response } from 'express';
import { getClientIp } from '../utils/client-ip';
import { AuthService } from './auth.service';
import { AuthSessionGuard, RequestWithSession } from './auth-session.guard';
import { ActivatePromoDto } from './dto/activate-promo.dto';
import { CheckTopupDto } from './dto/check-topup.dto';
import { CompletePasswordResetDto } from './dto/complete-password-reset.dto';
import { RemoveDeviceDto } from './dto/remove-device.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { CreateTopupDto } from './dto/create-topup.dto';
import { LoginTelegramOtpDto } from './dto/login-telegram-otp.dto';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { RequestPasswordResetDto } from './dto/request-password-reset.dto';
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
  @UseGuards(ThrottlerGuard)
  @Throttle({ default: { limit: 120, ttl: 60000 } })
  captchaConfig() {
    return this.auth.getCaptchaConfig();
  }

  @Get('telegram-widget-config')
  telegramWidgetConfig() {
    return this.auth.getTelegramWidgetConfig();
  }

  @Post('register')
  @UseGuards(ThrottlerGuard)
  @Throttle({ default: { limit: 15, ttl: 60000 } })
  async register(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Body() body: RegisterDto,
  ) {
    const result = await this.auth.register(body, getClientIp(req));
    this.setCookie(res, result.token);
    return { ok: true, message: result.message, user: result.user };
  }

  @Post('login')
  @UseGuards(ThrottlerGuard)
  @Throttle({ default: { limit: 20, ttl: 60000 } })
  async login(
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @Body() body: LoginDto,
  ) {
    const result = await this.auth.login(body, getClientIp(req));
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
  @UseGuards(ThrottlerGuard)
  @Throttle({ default: { limit: 25, ttl: 60000 } })
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

  @Post('password-reset/request')
  @UseGuards(ThrottlerGuard)
  @Throttle({ default: { limit: 8, ttl: 60000 } })
  async requestPasswordReset(
    @Req() req: Request,
    @Body() body: RequestPasswordResetDto,
  ) {
    return this.auth.requestPasswordReset(body, getClientIp(req));
  }

  @Post('password-reset/complete')
  async completePasswordReset(
    @Body() body: CompletePasswordResetDto,
  ) {
    return this.auth.completePasswordReset(
      body.challengeId,
      body.code,
      body.newPassword,
      body.confirmPassword,
    );
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
  @UseGuards(ThrottlerGuard)
  @Throttle({ default: { limit: 20, ttl: 60000 } })
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

  @Post('promo/activate')
  @UseGuards(AuthSessionGuard)
  async activatePromo(
    @Req() req: RequestWithSession,
    @Body() body: ActivatePromoDto,
  ) {
    const u = req.sessionUser;
    if (!u) throw new UnauthorizedException();
    return this.auth.activatePromo(u.id, body);
  }

  @Post('bonus/trial')
  @UseGuards(AuthSessionGuard)
  async claimTrialBonus(@Req() req: RequestWithSession) {
    const u = req.sessionUser;
    if (!u) throw new UnauthorizedException();
    return this.auth.claimTrialBonus(u.id);
  }

  @Post('bonus/telegram-link')
  @UseGuards(AuthSessionGuard)
  async claimTelegramLinkBonus(@Req() req: RequestWithSession) {
    const u = req.sessionUser;
    if (!u) throw new UnauthorizedException();
    return this.auth.claimTelegramLinkBonus(u.id);
  }

  @Post('topup/create')
  @UseGuards(AuthSessionGuard)
  async createTopup(
    @Req() req: RequestWithSession,
    @Body() body: CreateTopupDto,
  ) {
    const u = req.sessionUser;
    if (!u) throw new UnauthorizedException();
    return this.auth.createTopup(u.id, body);
  }

  @Post('topup/check')
  @UseGuards(AuthSessionGuard)
  async checkTopup(
    @Req() req: RequestWithSession,
    @Body() body: CheckTopupDto,
  ) {
    const u = req.sessionUser;
    if (!u) throw new UnauthorizedException();
    return this.auth.checkTopup(u.id, body.paymentId);
  }

  @Get('payments')
  @UseGuards(AuthSessionGuard)
  async listPayments(
    @Req() req: RequestWithSession,
    @Query('limit') limit?: string,
  ) {
    const u = req.sessionUser;
    if (!u) throw new UnauthorizedException();
    return this.auth.listPayments(u.id, limit ? Number(limit) : 50);
  }

  /** Резервный endpoint; в продакшене в Platega укажите webhook на бота: https://bot.amnesiavps.ru/platega/webhook */
  @Post('topup/platega/webhook')
  async plategaWebhook(@Req() req: Request) {
    return this.auth.processPlategaWebhook(req.body);
  }

  @Post('subscription/device/remove')
  @UseGuards(AuthSessionGuard)
  async removeSubscriptionDevice(
    @Req() req: RequestWithSession,
    @Body() body: RemoveDeviceDto,
  ) {
    const u = req.sessionUser;
    if (!u) throw new UnauthorizedException();
    return this.auth.removeSubscriptionDevice(u.id, body.hwid);
  }
}
