import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';
import { SiteAdminService } from './site-admin.service';

@Injectable()
export class SiteAdminGuard implements CanActivate {
  constructor(private readonly siteAdmin: SiteAdminService) {}

  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<Request>();
    const ok = this.siteAdmin.verifyJwtFromRequest(req);
    if (!ok) throw new UnauthorizedException();
    return true;
  }
}
