import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { createApp } from '../src/create-app';

async function generate(): Promise<void> {
  process.env.NODE_ENV = 'test';
  const app = await createApp();
  await app.init();
  const config = new DocumentBuilder()
    .setTitle('RN Foundation API')
    .setDescription('Mobile bootstrap, localization, theme and update policy')
    .setVersion('1.0.0')
    .addCookieAuth('rn_admin_session')
    .build();
  const document = SwaggerModule.createDocument(app, config);
  const output = resolve(process.cwd(), 'contracts/openapi.json');
  mkdirSync(dirname(output), { recursive: true });
  writeFileSync(output, `${JSON.stringify(document, null, 2)}\n`, 'utf8');
  await app.close();
}

void generate();
