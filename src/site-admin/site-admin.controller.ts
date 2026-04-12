import {
  Body,
  Controller,
  Get,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { Throttle, ThrottlerGuard } from '@nestjs/throttler';
import { Request, Response } from 'express';
import { SiteAdminLoginDto } from './dto/site-admin-login.dto';
import { SiteAdminVerifyOtpDto } from './dto/site-admin-verify-otp.dto';
import { SiteAdminGuard } from './site-admin.guard';
import { SiteAdminService } from './site-admin.service';

@Controller('api/site-admin')
export class SiteAdminController {
  constructor(private readonly siteAdmin: SiteAdminService) {}

  private setAdminCookie(res: Response, token: string) {
    res.cookie(this.siteAdmin.getCookieName(), token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 8 * 60 * 60 * 1000,
      path: '/',
    });
  }

  private clearAdminCookie(res: Response) {
    res.clearCookie(this.siteAdmin.getCookieName(), { path: '/' });
  }

  @Post('login')
  @UseGuards(ThrottlerGuard)
  @Throttle({ default: { limit: 8, ttl: 60000 } })
  async login(@Body() body: SiteAdminLoginDto) {
    return this.siteAdmin.requestLoginStep1(body);
  }

  @Post('verify')
  @UseGuards(ThrottlerGuard)
  @Throttle({ default: { limit: 25, ttl: 60000 } })
  async verify(
    @Body() body: SiteAdminVerifyOtpDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const token = this.siteAdmin.verifyOtpAndSignJwt(body);
    this.setAdminCookie(res, token);
    return { ok: true };
  }

  @Post('logout')
  logout(@Res({ passthrough: true }) res: Response) {
    this.clearAdminCookie(res);
    return { ok: true };
  }

  @Get('franchises')
  @UseGuards(SiteAdminGuard)
  async franchises() {
    return this.siteAdmin.getFranchisesDashboard();
  }

  @Get('session')
  session(@Req() req: Request) {
    return { ok: this.siteAdmin.verifyJwtFromRequest(req) };
  }
}
