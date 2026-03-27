import { Module } from '@nestjs/common';
import { RemnawaveController } from './remnawave.controller';
import { RemnawaveService } from './remnawave.service';

@Module({
  controllers: [RemnawaveController],
  providers: [RemnawaveService],
})
export class RemnawaveModule {}
