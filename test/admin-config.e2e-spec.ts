import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { createApp } from '../src/create-app';

type ManagedConfig = {
  configVersion: string;
  ttlSeconds: number;
  localization: unknown;
  theme: unknown;
  features: Record<string, boolean>;
  updatePolicy: unknown;
  support: unknown;
};

type ConfigView = {
  config: ManagedConfig;
  metadata: { databaseVersion: number; updatedBy: string; updatedAt: string };
};

describe('admin app configuration (e2e)', () => {
  let app: NestFastifyApplication;

  const auth = {
    'x-admin-key': 'local-development-admin-key-please-change',
    'x-admin-id': 'config-qa-admin',
  };

  beforeAll(async () => {
    app = await createApp();
    await app.init();
    await app.getHttpAdapter().getInstance().ready();
  });

  afterAll(async () => {
    await app.close();
  });

  it('allows the admin web app to preflight PATCH requests', async () => {
    const response = await app.inject({
      method: 'OPTIONS',
      url: '/v1/admin/app-config',
      headers: {
        origin: 'http://localhost:5173',
        'access-control-request-method': 'PATCH',
        'access-control-request-headers':
          'content-type,x-admin-key,x-admin-id,x-request-id',
      },
    });
    expect(response.statusCode).toBe(204);
    expect(response.headers['access-control-allow-methods']).toContain('PATCH');
    expect(response.headers['access-control-allow-headers']).toContain(
      'x-admin-key',
    );
  });

  it('saves a complete config transactionally and exposes it to bootstrap', async () => {
    const currentResponse = await app.inject({
      method: 'GET',
      url: '/v1/admin/app-config',
      headers: auth,
    });
    expect(currentResponse.statusCode).toBe(200);
    const current = currentResponse.json<ConfigView>();
    const changed = structuredClone(current.config);
    changed.ttlSeconds =
      current.config.ttlSeconds === 86400
        ? 86399
        : current.config.ttlSeconds + 1;

    let saved: ConfigView | undefined;
    try {
      const saveResponse = await app.inject({
        method: 'PATCH',
        url: '/v1/admin/app-config',
        headers: { ...auth, 'x-request-id': 'config-save-e2e' },
        payload: {
          config: changed,
          expectedVersion: current.metadata.databaseVersion,
          reason: 'verify admin configuration editing',
          confirm: true,
        },
      });
      expect(saveResponse.statusCode).toBe(200);
      saved = saveResponse.json<ConfigView>();
      expect(saved).toMatchObject({
        status: 'active',
        config: { ttlSeconds: changed.ttlSeconds },
        metadata: {
          databaseVersion: current.metadata.databaseVersion + 1,
          updatedBy: 'config-qa-admin',
        },
      });

      const staleWrite = await app.inject({
        method: 'PATCH',
        url: '/v1/admin/app-config',
        headers: auth,
        payload: {
          config: current.config,
          expectedVersion: current.metadata.databaseVersion,
          reason: 'stale edit must be rejected',
          confirm: true,
        },
      });
      expect(staleWrite.statusCode).toBe(409);

      const bootstrap = await app.inject({
        method: 'GET',
        url: '/v1/mobile/bootstrap?locale=zh-CN',
      });
      expect(bootstrap.statusCode).toBe(200);
      expect(bootstrap.json()).toMatchObject({
        ttlSeconds: changed.ttlSeconds,
      });

      const audits = await app.inject({
        method: 'GET',
        url: '/v1/admin/audit-events',
        headers: auth,
      });
      expect(audits.json<{ items: unknown[] }>().items).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            actorId: 'config-qa-admin',
            action: 'config_update',
            requestId: 'config-save-e2e',
          }),
        ]),
      );
    } finally {
      if (saved) {
        const restoreResponse = await app.inject({
          method: 'PATCH',
          url: '/v1/admin/app-config',
          headers: auth,
          payload: {
            config: current.config,
            expectedVersion: saved.metadata.databaseVersion,
            reason: 'restore configuration after e2e',
            confirm: true,
          },
        });
        expect(restoreResponse.statusCode).toBe(200);
      }
    }
  });
});
