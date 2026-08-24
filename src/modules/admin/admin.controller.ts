import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Headers,
  Param,
  Patch,
  Post,
  Query,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBody,
  ApiCookieAuth,
  ApiHeader,
  ApiOperation,
  ApiResponse,
  ApiTags,
  type SchemaObject,
} from '@nestjs/swagger';
import { z } from 'zod';
import { AdminAuthGuard } from './admin-auth.guard';
import { AppReleaseService } from '../app-release/app-release.service';
import { AppConfigService } from '../app-config/app-config.service';

const createReleaseSchema = z.object({
  applicationId: z.string().min(1),
  platform: z.enum(['android', 'ios']),
  version: z.string().min(1),
  buildNumber: z.number().int().positive(),
  runtimeVersion: z.string().min(1),
  channel: z.enum(['store', 'direct', 'mdm', 'ota']),
  releaseNotes: z.array(z.string().min(1)).default([]),
  artifact: z
    .object({
      id: z.string(),
      fileName: z.string(),
      downloadUrl: z.string().url().nullable(),
      size: z.number().nonnegative(),
      sha256: z.string().min(8),
      signingFingerprint: z.string().nullable(),
      minOsVersion: z.string(),
    })
    .nullable()
    .optional(),
  rollout: z
    .object({
      percentage: z.number().min(0).max(100),
      audience: z.string(),
      startsAt: z.string().nullable(),
      stopRule: z.string().nullable(),
    })
    .partial()
    .optional(),
});
const actionSchema = z.object({
  reason: z.string().min(3),
  confirm: z.literal(true),
});
const configUpdateSchema = z.object({
  reason: z.string().trim().min(3),
  confirm: z.literal(true),
  expectedVersion: z.number().int().positive(),
  config: z.unknown(),
});

const paletteOpenApiSchema: SchemaObject = {
  type: 'object',
  required: [
    'primary',
    'onPrimary',
    'background',
    'surface',
    'surfaceVariant',
    'text',
    'textMuted',
    'border',
    'success',
    'warning',
    'danger',
    'info',
    'pricePositive',
    'priceNegative',
    'risk',
    'focus',
    'backdrop',
  ],
  properties: {
    primary: { type: 'string' },
    onPrimary: { type: 'string' },
    background: { type: 'string' },
    surface: { type: 'string' },
    surfaceVariant: { type: 'string' },
    text: { type: 'string' },
    textMuted: { type: 'string' },
    border: { type: 'string' },
    success: { type: 'string' },
    warning: { type: 'string' },
    danger: { type: 'string' },
    info: { type: 'string' },
    pricePositive: { type: 'string' },
    priceNegative: { type: 'string' },
    risk: { type: 'string' },
    focus: { type: 'string' },
    backdrop: { type: 'string' },
  },
};

const managedConfigOpenApiSchema: SchemaObject = {
  type: 'object',
  required: [
    'configVersion',
    'ttlSeconds',
    'localization',
    'theme',
    'features',
    'updatePolicy',
    'support',
  ],
  properties: {
    configVersion: { type: 'string' },
    ttlSeconds: { type: 'integer', minimum: 30, maximum: 86400 },
    localization: {
      type: 'object',
      required: [
        'fallbackLocale',
        'supportedLocales',
        'messagesVersion',
        'messages',
      ],
      properties: {
        fallbackLocale: { enum: ['zh-CN', 'en-US'] },
        supportedLocales: {
          type: 'array',
          items: { enum: ['zh-CN', 'en-US'] },
        },
        messagesVersion: { type: 'string' },
        messages: {
          type: 'object',
          required: ['zh-CN', 'en-US'],
          properties: {
            'zh-CN': {
              type: 'object',
              additionalProperties: { type: 'string' },
            },
            'en-US': {
              type: 'object',
              additionalProperties: { type: 'string' },
            },
          },
        },
      },
    },
    theme: {
      type: 'object',
      required: [
        'defaultMode',
        'allowUserOverride',
        'paletteVersion',
        'light',
        'dark',
      ],
      properties: {
        defaultMode: { type: 'string', enum: ['system'] },
        allowUserOverride: { type: 'boolean' },
        paletteVersion: { type: 'string' },
        light: paletteOpenApiSchema,
        dark: paletteOpenApiSchema,
      },
    },
    features: {
      type: 'object',
      required: [
        'updateCenter',
        'otaEnabled',
        'directUpdateEnabled',
        'diagnosticsEnabled',
      ],
      properties: {
        updateCenter: { type: 'boolean' },
        otaEnabled: { type: 'boolean' },
        directUpdateEnabled: { type: 'boolean' },
        diagnosticsEnabled: { type: 'boolean' },
      },
    },
    updatePolicy: {
      type: 'object',
      required: ['minSupportedVersion', 'latestVersion', 'otaChannel'],
      properties: {
        minSupportedVersion: { type: 'string' },
        latestVersion: { type: 'string' },
        otaChannel: { type: 'string' },
      },
    },
    support: {
      type: 'object',
      required: ['statusPageUrl'],
      properties: { statusPageUrl: { type: 'string', format: 'uri' } },
    },
  },
};

const adminConfigViewOpenApiSchema: SchemaObject & {
  required: string[];
  properties: NonNullable<SchemaObject['properties']>;
} = {
  type: 'object',
  required: ['summary', 'config', 'metadata'],
  properties: {
    summary: {
      type: 'object',
      description: 'Compact presentation summary of the active config',
    },
    config: managedConfigOpenApiSchema,
    metadata: {
      type: 'object',
      required: ['databaseVersion', 'updatedBy', 'updatedAt'],
      properties: {
        databaseVersion: { type: 'integer', minimum: 1 },
        updatedBy: { type: 'string' },
        updatedAt: { type: 'string', format: 'date-time' },
      },
    },
  },
};

@ApiTags('admin')
@Controller('v1/admin')
@UseGuards(AdminAuthGuard)
@ApiCookieAuth('rn_admin_session')
@ApiHeader({ name: 'X-Admin-Key', required: false })
@ApiHeader({ name: 'X-Admin-Id', required: false })
export class AdminController {
  constructor(
    private readonly releases: AppReleaseService,
    private readonly appConfig: AppConfigService,
  ) {}

  @Get('overview')
  @ApiOperation({ summary: 'Release operations dashboard summary' })
  @ApiResponse({
    status: 200,
    description: 'Current releases and rollout summary',
  })
  overview() {
    return {
      generatedAt: new Date().toISOString(),
      ...this.releases.overview(),
      signals: {
        crashFreeSessions: null,
        updateSuccessRate: null,
        note: 'Connect telemetry provider before production SLO decisions',
      },
    };
  }

  @Get('releases')
  list(@Query('platform') platform?: string, @Query('status') status?: string) {
    return {
      items: this.releases.list({ platform, status }),
      nextCursor: null,
      hasMore: false,
    };
  }

  @Post('releases')
  @ApiBody({
    description: 'Release metadata and optional verified artifact',
    schema: {
      type: 'object',
      required: [
        'applicationId',
        'platform',
        'version',
        'buildNumber',
        'runtimeVersion',
        'channel',
      ],
      properties: {
        applicationId: { type: 'string' },
        platform: { enum: ['android', 'ios'] },
        version: { type: 'string' },
        buildNumber: { type: 'integer' },
        runtimeVersion: { type: 'string' },
        channel: { enum: ['store', 'direct', 'mdm', 'ota'] },
        releaseNotes: { type: 'array', items: { type: 'string' } },
        artifact: { type: 'object', nullable: true },
        rollout: { type: 'object' },
      },
    },
  })
  async create(
    @Body() body: unknown,
    @Headers('x-admin-id') actorId = 'unknown',
    @Headers('x-request-id') requestId = 'admin-request',
  ) {
    const parsed = createReleaseSchema.safeParse(body);
    if (!parsed.success)
      throw new BadRequestException('Invalid release payload');
    const release = await this.releases.create(parsed.data, actorId, requestId);
    return { release, audit: { actorId, requestId, action: 'create' } };
  }

  @Get('releases/:id')
  detail(@Param('id') id: string) {
    return {
      release: this.releases.get(id),
      audits: this.releases.audits().filter((audit) => audit.targetId === id),
    };
  }

  @Post('releases/:id/:action')
  @ApiBody({
    description: 'High-risk action confirmation',
    schema: {
      type: 'object',
      required: ['reason', 'confirm'],
      properties: {
        reason: { type: 'string', minLength: 3 },
        confirm: { type: 'boolean', enum: [true] },
      },
    },
  })
  async action(
    @Param('id') id: string,
    @Param('action') action: string,
    @Body() body: unknown,
    @Headers('x-admin-id') actorId = 'unknown',
    @Headers('x-request-id') requestId = 'admin-request',
  ) {
    const parsed = actionSchema.safeParse(body);
    if (!parsed.success)
      throw new BadRequestException('reason and confirm=true are required');
    if (!['verify', 'stage', 'activate', 'pause', 'rollback'].includes(action))
      throw new BadRequestException('Unsupported release action');
    const target =
      action === 'verify'
        ? 'verified'
        : action === 'stage'
          ? 'staged'
          : action === 'activate'
            ? 'active'
            : action === 'pause'
              ? 'paused'
              : 'rolled_back';
    return {
      release: await this.releases.transition(
        id,
        target,
        actorId,
        parsed.data.reason,
        requestId,
        action,
      ),
    };
  }

  @Get('audit-events')
  audits() {
    return { items: this.releases.audits(), nextCursor: null, hasMore: false };
  }

  @Get('app-config')
  @ApiOperation({ summary: 'Get the complete active mobile configuration' })
  @ApiResponse({
    status: 200,
    description: 'Configuration, summary and MySQL revision metadata',
    schema: adminConfigViewOpenApiSchema,
  })
  config() {
    return this.appConfig.adminView();
  }

  @Patch('app-config')
  @ApiOperation({ summary: 'Validate and activate mobile configuration' })
  @ApiBody({
    schema: {
      type: 'object',
      required: ['reason', 'confirm', 'expectedVersion', 'config'],
      properties: {
        reason: { type: 'string', minLength: 3 },
        confirm: { type: 'boolean', enum: [true] },
        expectedVersion: { type: 'integer', minimum: 1 },
        config: managedConfigOpenApiSchema,
      },
    },
  })
  @ApiResponse({
    status: 200,
    description: 'The active configuration after a transactional save',
    schema: {
      type: 'object',
      required: [
        'status',
        'savedAt',
        'actorId',
        'requestId',
        ...adminConfigViewOpenApiSchema.required,
      ],
      properties: {
        status: { type: 'string', enum: ['active'] },
        savedAt: { type: 'string', format: 'date-time' },
        actorId: { type: 'string' },
        requestId: { type: 'string' },
        ...adminConfigViewOpenApiSchema.properties,
      },
    },
  })
  @ApiResponse({ status: 400, description: 'Config validation failed' })
  @ApiResponse({ status: 409, description: 'Config revision is stale' })
  async updateConfig(
    @Body() body: unknown,
    @Headers('x-admin-id') actorId = 'unknown',
    @Headers('x-request-id') requestId = 'admin-request',
  ) {
    const parsed = configUpdateSchema.safeParse(body);
    if (!parsed.success) {
      throw new BadRequestException(
        'config, expectedVersion, reason and confirm=true are required',
      );
    }
    const savedAt = new Date().toISOString();
    const view = await this.appConfig.replace({
      value: parsed.data.config,
      expectedVersion: parsed.data.expectedVersion,
      actorId,
      reason: parsed.data.reason,
      requestId,
    });
    return {
      status: 'active',
      savedAt,
      actorId,
      requestId,
      ...view,
    };
  }
}
