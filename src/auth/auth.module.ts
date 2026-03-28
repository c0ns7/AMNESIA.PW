import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { AuthSessionGuard } from './auth-session.guard';
import { InternalController } from './internal.controller';

@Module({
  controllers: [AuthController, InternalController],
  providers: [AuthService, AuthSessionGuard],
  exports: [AuthService],
})
export class AuthModule {}
