import {
  HttpException,
  HttpStatus,
  Injectable,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { RowDataPacket } from 'mysql2/promise';
import { getEnvironment } from '../../platform/config/env';
import { MysqlService } from '../../platform/database/mysql.service';
import { verifyAdminPassword } from './password-hash';

const SESSION_COOKIE = 'rn_admin_session';

type SessionRow = RowDataPacket & {
  actor_id: string;
  expires_at: Date;
};

type AttemptWindow = { failures: number; resetsAt: number };

export type AdminPrincipal = {
  actorId: string;
  expiresAt: string | null;
  method: 'session' | 'api-key';
};

export type AdminRequestContext = {
  adminPrincipal?: AdminPrincipal;
};

@Injectable()
export class AdminSessionService {
  private readonly attempts = new Map<string, AttemptWindow>();

  constructor(private readonly database: MysqlService) {}

  async login(
    username: string,
    password: string,
    clientAddress: string,
  ): Promise<{ token: string; principal: AdminPrincipal }> {
    const environment = getEnvironment();
    if (!environment.ADMIN_USERNAME || !environment.ADMIN_PASSWORD_HASH) {
      throw new ServiceUnavailableException('Admin login is not configured');
    }
    const actorId = environment.ADMIN_USERNAME;
    const passwordHash = environment.ADMIN_PASSWORD_HASH;
    this.assertNotRateLimited(clientAddress);

    const usernameMatches = this.constantTimeTextEqual(username, actorId);
    const passwordMatches = await verifyAdminPassword(password, passwordHash);
    if (!usernameMatches || !passwordMatches) {
      this.recordFailure(clientAddress);
      throw new UnauthorizedException('Invalid username or password');
    }

    this.attempts.delete(clientAddress);
    const token = randomBytes(32).toString('base64url');
    const now = new Date();
    const expiresAt = new Date(
      now.getTime() + environment.ADMIN_SESSION_TTL_SECONDS * 1000,
    );
    await this.database.transaction(async (connection) => {
      await connection.execute(
        'DELETE FROM admin_sessions WHERE expires_at <= ?',
        [now],
      );
      await connection.execute(
        `INSERT INTO admin_sessions
         (token_hash, actor_id, expires_at, created_at)
         VALUES (?, ?, ?, ?)`,
        [this.tokenHash(token), actorId, expiresAt, now],
      );
    });
    return {
      token,
      principal: {
        actorId,
        expiresAt: expiresAt.toISOString(),
        method: 'session',
      },
    };
  }

  async authenticate(cookieHeader?: string): Promise<AdminPrincipal | null> {
    const token = this.readCookie(cookieHeader);
    if (!token) return null;
    const rows = await this.database.query<SessionRow[]>(
      `SELECT actor_id, expires_at
       FROM admin_sessions
       WHERE token_hash = ? AND expires_at > ?
       LIMIT 1`,
      [this.tokenHash(token), new Date()],
    );
    const session = rows[0];
    if (!session) return null;
    return {
      actorId: session.actor_id,
      expiresAt: session.expires_at.toISOString(),
      method: 'session',
    };
  }

  async logout(cookieHeader?: string): Promise<void> {
    const token = this.readCookie(cookieHeader);
    if (!token) return;
    await this.database.execute(
      'DELETE FROM admin_sessions WHERE token_hash = ?',
      [this.tokenHash(token)],
    );
  }

  cookie(token: string): string {
    const environment = getEnvironment();
    return [
      `${SESSION_COOKIE}=${encodeURIComponent(token)}`,
      `Max-Age=${environment.ADMIN_SESSION_TTL_SECONDS}`,
      'Path=/v1/admin',
      'HttpOnly',
      'SameSite=Strict',
      environment.ADMIN_COOKIE_SECURE ? 'Secure' : '',
    ]
      .filter(Boolean)
      .join('; ');
  }

  clearCookie(): string {
    return [
      `${SESSION_COOKIE}=`,
      'Max-Age=0',
      'Path=/v1/admin',
      'HttpOnly',
      'SameSite=Strict',
      getEnvironment().ADMIN_COOKIE_SECURE ? 'Secure' : '',
    ]
      .filter(Boolean)
      .join('; ');
  }

  private readCookie(cookieHeader?: string): string | null {
    if (!cookieHeader) return null;
    for (const part of cookieHeader.split(';')) {
      const [name, ...valueParts] = part.trim().split('=');
      if (name !== SESSION_COOKIE) continue;
      const value = valueParts.join('=');
      try {
        return value ? decodeURIComponent(value) : null;
      } catch {
        return null;
      }
    }
    return null;
  }

  private assertNotRateLimited(clientAddress: string): void {
    const attempt = this.attempts.get(clientAddress);
    if (!attempt) return;
    if (attempt.resetsAt <= Date.now()) {
      this.attempts.delete(clientAddress);
      return;
    }
    if (attempt.failures >= getEnvironment().ADMIN_LOGIN_MAX_ATTEMPTS) {
      throw new HttpException(
        'Too many login attempts',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
  }

  private recordFailure(clientAddress: string): void {
    const now = Date.now();
    const existing = this.attempts.get(clientAddress);
    const resetsAt = now + getEnvironment().ADMIN_LOGIN_WINDOW_SECONDS * 1000;
    if (!existing || existing.resetsAt <= now) {
      this.attempts.set(clientAddress, { failures: 1, resetsAt });
      return;
    }
    existing.failures += 1;
  }

  private tokenHash(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  private constantTimeTextEqual(actual: string, expected: string): boolean {
    const actualHash = createHash('sha256').update(actual).digest();
    const expectedHash = createHash('sha256').update(expected).digest();
    return timingSafeEqual(actualHash, expectedHash);
  }
}
