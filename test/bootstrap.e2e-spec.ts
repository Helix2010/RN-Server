import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { createApp } from '../src/create-app';

describe('mobile bootstrap (e2e)', () => {
  let app: NestFastifyApplication;

  beforeAll(async () => {
    app = await createApp();
    await app.init();
    await app.getHttpAdapter().getInstance().ready();
  });

  afterAll(async () => {
    await app.close();
  });

  it('returns a validated configuration contract', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/v1/mobile/bootstrap?locale=zh-CN',
      headers: {
        'x-app-version': '1.0.0',
        'x-build-number': '1',
        'x-platform': 'android',
        'x-distribution-channel': 'direct',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers['x-request-id']).toBeDefined();
    expect(response.headers.etag).toBeDefined();
    expect(response.json()).toMatchObject({
      schemaVersion: 1,
      localization: { selectedLocale: 'zh-CN' },
      features: { updateCenter: true },
      app: { platform: 'android', distribution: 'direct' },
    });
  });
});
