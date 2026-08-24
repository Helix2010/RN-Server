import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { hashAdminPassword } from '../src/modules/admin/password-hash';
import { createApp } from '../src/create-app';

describe('admin browser authentication (e2e)', () => {
  let app: NestFastifyApplication;
  const username = 'session-qa-admin';
  const password = 'correct-horse-battery-staple';
  const origin = 'http://localhost:5173';

  beforeAll(async () => {
    process.env.ADMIN_USERNAME = username;
    process.env.ADMIN_PASSWORD_HASH = await hashAdminPassword(password);
    process.env.CORS_ORIGINS = origin;
    app = await createApp();
    await app.init();
    await app.getHttpAdapter().getInstance().ready();
  });

  afterAll(async () => {
    await app.close();
  });

  it('creates an HttpOnly session, guards APIs and revokes it on logout', async () => {
    const unauthenticated = await app.inject({
      method: 'GET',
      url: '/v1/admin/auth/session',
    });
    expect(unauthenticated.statusCode).toBe(401);

    const invalid = await app.inject({
      method: 'POST',
      url: '/v1/admin/auth/login',
      headers: { origin, 'x-forwarded-for': '198.51.100.10' },
      payload: { username, password: 'incorrect-password' },
    });
    expect(invalid.statusCode).toBe(401);
    expect(invalid.headers['set-cookie']).toBeUndefined();

    const login = await app.inject({
      method: 'POST',
      url: '/v1/admin/auth/login',
      headers: { origin, 'x-forwarded-for': '198.51.100.11' },
      payload: { username, password },
    });
    expect(login.statusCode).toBe(200);
    expect(login.json()).toMatchObject({
      authenticated: true,
      actorId: username,
      method: 'session',
    });
    const setCookie = login.headers['set-cookie'];
    expect(setCookie).toEqual(expect.stringContaining('HttpOnly'));
    expect(setCookie).toEqual(expect.stringContaining('SameSite=Strict'));
    const cookie = String(setCookie).split(';', 1)[0];

    const overview = await app.inject({
      method: 'GET',
      url: '/v1/admin/overview',
      headers: { cookie },
    });
    expect(overview.statusCode).toBe(200);

    const untrustedMutation = await app.inject({
      method: 'POST',
      url: '/v1/admin/auth/logout',
      headers: { cookie, origin: 'https://attacker.example' },
    });
    expect(untrustedMutation.statusCode).toBe(403);

    const logout = await app.inject({
      method: 'POST',
      url: '/v1/admin/auth/logout',
      headers: { cookie, origin },
    });
    expect(logout.statusCode).toBe(200);
    expect(logout.headers['set-cookie']).toEqual(
      expect.stringContaining('Max-Age=0'),
    );

    const revoked = await app.inject({
      method: 'GET',
      url: '/v1/admin/overview',
      headers: { cookie },
    });
    expect(revoked.statusCode).toBe(401);
  });

  it('rate limits repeated invalid login attempts per client address', async () => {
    for (let attempt = 0; attempt < 5; attempt += 1) {
      const response = await app.inject({
        method: 'POST',
        url: '/v1/admin/auth/login',
        headers: { origin, 'x-forwarded-for': '198.51.100.20' },
        payload: { username, password: 'incorrect-password' },
      });
      expect(response.statusCode).toBe(401);
    }
    const blocked = await app.inject({
      method: 'POST',
      url: '/v1/admin/auth/login',
      headers: { origin, 'x-forwarded-for': '198.51.100.20' },
      payload: { username, password },
    });
    expect(blocked.statusCode).toBe(429);
  });
});
