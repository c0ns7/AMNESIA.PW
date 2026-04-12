import { Module } from '@nestjs/common';
import { SiteAdminController } from './site-admin.controller';
import { SiteAdminGuard } from './site-admin.guard';
import { SiteAdminService } from './site-admin.service';

@Module({
  controllers: [SiteAdminController],
  providers: [SiteAdminService, SiteAdminGuard],
  exports: [SiteAdminService],
})
export class SiteAdminModule {}
