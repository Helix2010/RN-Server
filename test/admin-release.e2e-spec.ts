import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { createApp } from '../src/create-app';

describe('admin release management (e2e)', () => {
  let app: NestFastifyApplication;

  beforeAll(async () => {
    app = await createApp();
    await app.init();
    await app.getHttpAdapter().getInstance().ready();
  });

  afterAll(async () => {
    await app.close();
  });

  const auth = {
    'x-admin-key': 'local-development-admin-key-please-change',
    'x-admin-id': 'qa-admin',
  };

  const parseJson = <T>(response: { body: string }): T =>
    JSON.parse(response.body) as T;

  it('rejects unauthenticated admin access', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/v1/admin/overview',
    });
    expect(response.statusCode).toBe(401);
    expect(response.headers['content-type']).toContain(
      'application/problem+json',
    );
  });

  it('runs a release through guarded state transitions and records audit', async () => {
    const buildNumber = Math.floor(Date.now() / 1000);
    const version = `1.2.${buildNumber}`;
    const created = await app.inject({
      method: 'POST',
      url: '/v1/admin/releases',
      headers: auth,
      payload: {
        applicationId: 'dex-mobile',
        platform: 'android',
        version,
        buildNumber,
        runtimeVersion: 'expo:57.0.15',
        channel: 'direct',
        releaseNotes: ['灰度修复'],
        artifact: {
          id: 'artifact-120',
          fileName: 'dex.apk',
          downloadUrl: 'https://example.com/dex.apk',
          size: 100,
          sha256: '12345678-sha',
          signingFingerprint: 'fingerprint',
          minOsVersion: '8.0',
        },
        rollout: {
          percentage: 10,
          audience: 'internal',
          startsAt: null,
          stopRule: 'crash-free < 99%',
        },
      },
    });
    expect(created.statusCode).toBe(201);
    const id = parseJson<{ release: { id: string } }>(created).release.id;
    for (const [action, status] of [
      ['verify', 'verified'],
      ['stage', 'staged'],
      ['activate', 'active'],
    ] as const) {
      const response = await app.inject({
        method: 'POST',
        url: `/v1/admin/releases/${id}/${action}`,
        headers: { ...auth, 'x-request-id': `qa-${action}` },
        payload: { reason: `qa ${action}`, confirm: true },
      });
      expect(response.statusCode).toBe(201);
      expect(
        parseJson<{ release: { lastAction: string } }>(response).release
          .lastAction,
      ).toBe(status);
    }
    const audits = await app.inject({
      method: 'GET',
      url: '/v1/admin/audit-events',
      headers: auth,
    });
    expect(audits.statusCode).toBe(200);
    expect(parseJson<{ items: unknown[] }>(audits).items).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          targetId: id,
          action: 'activate',
          actorId: 'qa-admin',
        }),
      ]),
    );
  });
});
