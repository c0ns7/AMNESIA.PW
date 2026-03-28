import { Module } from '@nestjs/common';
import { RemnawaveModule } from '../remnawave/remnawave.module';
import { SubscriptionModule } from '../subscription/subscription.module';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { AuthSessionGuard } from './auth-session.guard';
import { InternalController } from './internal.controller';

@Module({
  imports: [RemnawaveModule, SubscriptionModule],
  controllers: [AuthController, InternalController],
  providers: [AuthService, AuthSessionGuard],
  exports: [AuthService],
})
export class AuthModule {}
