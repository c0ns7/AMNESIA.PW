import { Module } from '@nestjs/common';
import { SubscriptionController } from './subscription.controller';
import { SubscriptionLinkService } from './subscription-link.service';

@Module({
  controllers: [SubscriptionController],
  providers: [SubscriptionLinkService],
  exports: [SubscriptionLinkService],
})
export class SubscriptionModule {}
