import { Module } from '@nestjs/common';
import { RemnawaveController } from './remnawave.controller';
import { RemnawaveService } from './remnawave.service';

@Module({
  controllers: [RemnawaveController],
  providers: [RemnawaveService],
  exports: [RemnawaveService],
})
export class RemnawaveModule {}
