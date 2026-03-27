import { Body, Controller, Get, Post, Req } from '@nestjs/common';
import { Request } from 'express';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';

@Controller('api/auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Get('captcha-config')
  captchaConfig() {
    return this.auth.getCaptchaConfig();
  }

  @Post('register')
  register(@Req() req: Request, @Body() body: RegisterDto) {
    return this.auth.register(body, req.ip);
  }

  @Post('login')
  login(@Req() req: Request, @Body() body: LoginDto) {
    return this.auth.login(body, req.ip);
  }
}
