import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { createHash, timingSafeEqual } from 'node:crypto';
import type { FastifyRequest } from 'fastify';
import { getEnvironment } from '../../platform/config/env';
import {
  type AdminRequestContext,
  AdminSessionService,
} from './admin-session.service';

/**
 * Development-friendly boundary until the platform is connected to OIDC.
 * Production must replace the shared key with a verified admin JWT gateway.
 */
@Injectable()
export class AdminAuthGuard implements CanActivate {
  constructor(private readonly sessions: AdminSessionService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context
      .switchToHttp()
      .getRequest<FastifyRequest & AdminRequestContext>();
    const session = await this.sessions.authenticate(request.headers.cookie);
    if (session) {
      this.assertTrustedOrigin(request);
      request.adminPrincipal = session;
      request.headers['x-admin-id'] = session.actorId;
      return true;
    }

    const environment = getEnvironment();
    const key = request.headers['x-admin-key'];
    const actor = request.headers['x-admin-id'];
    const expectedKey = environment.ADMIN_API_KEY;
    if (
      !expectedKey ||
      typeof key !== 'string' ||
      !this.constantTimeEqual(key, expectedKey) ||
      typeof actor !== 'string' ||
      actor.trim() === ''
    ) {
      throw new UnauthorizedException('Admin authentication required');
    }
    request.adminPrincipal = {
      actorId: actor,
      expiresAt: null,
      method: 'api-key',
    };
    return true;
  }

  private constantTimeEqual(actual: string, expected: string): boolean {
    const actualHash = createHash('sha256').update(actual).digest();
    const expectedHash = createHash('sha256').update(expected).digest();
    return timingSafeEqual(actualHash, expectedHash);
  }

  private assertTrustedOrigin(request: FastifyRequest): void {
    if (['GET', 'HEAD', 'OPTIONS'].includes(request.method)) return;
    const origin = request.headers.origin;
    const allowedOrigins = getEnvironment()
      .CORS_ORIGINS.split(',')
      .map((value) => value.trim());
    if (
      typeof origin !== 'string' ||
      (!allowedOrigins.includes('*') && !allowedOrigins.includes(origin))
    ) {
      throw new ForbiddenException('Untrusted admin request origin');
    }
  }
}
