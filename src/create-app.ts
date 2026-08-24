import helmet from '@fastify/helmet';
import { Logger } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import {
  FastifyAdapter,
  type NestFastifyApplication,
} from '@nestjs/platform-fastify';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { AppModule } from './app.module';
import { getEnvironment } from './platform/config/env';
import { ProblemDetailsFilter } from './platform/http/problem-details.filter';

export async function createApp(): Promise<NestFastifyApplication> {
  const environment = getEnvironment();
  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter({ logger: false, trustProxy: true }),
  );

  await app.register(helmet, { contentSecurityPolicy: false });
  app.enableCors({
    origin:
      environment.CORS_ORIGINS === '*'
        ? true
        : environment.CORS_ORIGINS.split(',').map((value) => value.trim()),
    methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    credentials: true,
    allowedHeaders: [
      'content-type',
      'x-admin-key',
      'x-admin-id',
      'x-request-id',
    ],
  });
  app.useGlobalFilters(new ProblemDetailsFilter());

  const swaggerConfig = new DocumentBuilder()
    .setTitle('RN Foundation API')
    .setDescription('Mobile bootstrap, localization, theme and update policy')
    .setVersion('1.0.0')
    .addCookieAuth('rn_admin_session')
    .build();
  const document = SwaggerModule.createDocument(app, swaggerConfig);
  SwaggerModule.setup('docs', app, document);

  app
    .getHttpAdapter()
    .getInstance()
    .addHook(
      'onSend',
      (
        request: { id: string },
        reply: { header(name: string, value: string): void },
        _payload: unknown,
        done: () => void,
      ) => {
        reply.header('x-request-id', request.id);
        done();
      },
    );

  app.useLogger(new Logger('RN-Server'));
  return app;
}
