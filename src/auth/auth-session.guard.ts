import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';
import { AuthService } from './auth.service';
import { SessionUser } from './session.types';

export type RequestWithSession = Request & { sessionUser?: SessionUser };

@Injectable()
export class AuthSessionGuard implements CanActivate {
  constructor(private readonly auth: AuthService) {}

  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<RequestWithSession>();
    const token = req.cookies?.['amnesia_auth'];
    if (!token || typeof token !== 'string') {
      throw new UnauthorizedException();
    }
    const user = this.auth.verifyAuthToken(token);
    if (!user) {
      throw new UnauthorizedException();
    }
    req.sessionUser = user;
    return true;
  }
}
