import {
  BadRequestException,
  ConflictException,
  Injectable,
  OnModuleInit,
} from '@nestjs/common';
import type { ResultSetHeader, RowDataPacket } from 'mysql2/promise';
import { gt, valid } from 'semver';
import { z } from 'zod';
import { MysqlService } from '../../platform/database/mysql.service';
import { AuditService } from '../audit/audit.service';
import type {
  SemanticPalette,
  SupportedLocale,
} from '../mobile-bootstrap/bootstrap.types';
import {
  LATEST_VERSION,
  MESSAGES_VERSION,
  MIN_SUPPORTED_VERSION,
  PALETTE_VERSION,
  messages,
  palettes,
} from '../mobile-bootstrap/foundation-config';

export type ManagedAppConfig = {
  configVersion: string;
  ttlSeconds: number;
  localization: {
    fallbackLocale: SupportedLocale;
    supportedLocales: SupportedLocale[];
    messagesVersion: string;
    messages: Record<SupportedLocale, Record<string, string>>;
  };
  theme: {
    defaultMode: 'system';
    allowUserOverride: boolean;
    paletteVersion: string;
    light: SemanticPalette;
    dark: SemanticPalette;
  };
  features: {
    updateCenter: boolean;
    otaEnabled: boolean;
    directUpdateEnabled: boolean;
    diagnosticsEnabled: boolean;
  };
  updatePolicy: {
    minSupportedVersion: string;
    latestVersion: string;
    otaChannel: string;
  };
  support: { statusPageUrl: string };
};

export type AppConfigMetadata = {
  databaseVersion: number;
  updatedBy: string;
  updatedAt: string;
};

type ConfigRow = RowDataPacket & {
  config_value: string | ManagedAppConfig;
  version: number;
  updated_by: string;
  updated_at: Date | string;
};

const paletteSchema = z.object({
  primary: z.string(),
  onPrimary: z.string(),
  background: z.string(),
  surface: z.string(),
  surfaceVariant: z.string(),
  text: z.string(),
  textMuted: z.string(),
  border: z.string(),
  success: z.string(),
  warning: z.string(),
  danger: z.string(),
  info: z.string(),
  pricePositive: z.string(),
  priceNegative: z.string(),
  risk: z.string(),
  focus: z.string(),
  backdrop: z.string(),
});
export const managedAppConfigSchema = z
  .object({
    configVersion: z.string().trim().min(1),
    ttlSeconds: z.number().int().min(30).max(86400),
    localization: z.object({
      fallbackLocale: z.enum(['zh-CN', 'en-US']),
      supportedLocales: z.array(z.enum(['zh-CN', 'en-US'])).min(1),
      messagesVersion: z.string().trim().min(1),
      messages: z.object({
        'zh-CN': z.record(z.string().min(1), z.string().min(1)),
        'en-US': z.record(z.string().min(1), z.string().min(1)),
      }),
    }),
    theme: z.object({
      defaultMode: z.literal('system'),
      allowUserOverride: z.boolean(),
      paletteVersion: z.string().trim().min(1),
      light: paletteSchema,
      dark: paletteSchema,
    }),
    features: z.object({
      updateCenter: z.boolean(),
      otaEnabled: z.boolean(),
      directUpdateEnabled: z.boolean(),
      diagnosticsEnabled: z.boolean(),
    }),
    updatePolicy: z.object({
      minSupportedVersion: z.string().trim().min(1),
      latestVersion: z.string().trim().min(1),
      otaChannel: z.string().trim().min(1),
    }),
    support: z.object({ statusPageUrl: z.string().url() }),
  })
  .superRefine((config, context) => {
    for (const locale of ['zh-CN', 'en-US'] as const) {
      if (!config.localization.supportedLocales.includes(locale)) {
        context.addIssue({
          code: 'custom',
          path: ['localization', 'supportedLocales'],
          message: `${locale} must remain supported`,
        });
      }
    }
    const zhKeys = Object.keys(config.localization.messages['zh-CN']).sort();
    const enKeys = Object.keys(config.localization.messages['en-US']).sort();
    if (zhKeys.join('\n') !== enKeys.join('\n')) {
      context.addIssue({
        code: 'custom',
        path: ['localization', 'messages'],
        message: 'Locale message keys must match',
      });
    }
    const minimum = valid(config.updatePolicy.minSupportedVersion);
    const latest = valid(config.updatePolicy.latestVersion);
    if (!minimum) {
      context.addIssue({
        code: 'custom',
        path: ['updatePolicy', 'minSupportedVersion'],
        message: 'Minimum version must be valid semver',
      });
    }
    if (!latest) {
      context.addIssue({
        code: 'custom',
        path: ['updatePolicy', 'latestVersion'],
        message: 'Latest version must be valid semver',
      });
    }
    if (minimum && latest && gt(minimum, latest)) {
      context.addIssue({
        code: 'custom',
        path: ['updatePolicy', 'minSupportedVersion'],
        message: 'Minimum version cannot exceed latest version',
      });
    }
  });

@Injectable()
export class AppConfigService implements OnModuleInit {
  private config?: ManagedAppConfig;
  private metadata?: AppConfigMetadata;

  constructor(
    private readonly database: MysqlService,
    private readonly audit: AuditService,
  ) {}

  async onModuleInit(): Promise<void> {
    const rows = await this.database.query<ConfigRow[]>(
      'SELECT config_value, version, updated_by, updated_at FROM app_configs WHERE config_key=?',
      ['mobile-bootstrap'],
    );
    if (rows[0]) {
      this.config = this.parse(rows[0].config_value);
      this.metadata = this.mapMetadata(rows[0]);
      return;
    }
    const initial = this.initialConfig();
    const now = new Date();
    await this.database.execute(
      `INSERT INTO app_configs (config_key, config_value, version, updated_by, updated_at) VALUES (?, ?, 1, ?, ?)`,
      ['mobile-bootstrap', JSON.stringify(initial), 'system-bootstrap', now],
    );
    this.config = initial;
    this.metadata = {
      databaseVersion: 1,
      updatedBy: 'system-bootstrap',
      updatedAt: now.toISOString(),
    };
  }

  get(): ManagedAppConfig {
    return structuredClone(this.requireConfig());
  }

  adminView() {
    return {
      summary: this.summary(),
      config: this.get(),
      metadata: structuredClone(this.requireMetadata()),
    };
  }

  summary() {
    const config = this.requireConfig();
    return {
      configVersion: config.configVersion,
      localization: {
        supportedLocales: config.localization.supportedLocales,
        messagesVersion: config.localization.messagesVersion,
      },
      theme: {
        paletteVersion: config.theme.paletteVersion,
        modes: ['light', 'dark'],
      },
      featureFlags: Object.entries(config.features)
        .filter(([, enabled]) => enabled)
        .map(([key]) => key),
      updatePolicy: { source: 'mysql', approvalRequired: false },
    };
  }

  async replace(input: {
    value: unknown;
    expectedVersion: number;
    actorId: string;
    reason: string;
    requestId: string;
  }) {
    const parsed = managedAppConfigSchema.safeParse(input.value);
    if (!parsed.success) {
      throw new BadRequestException({
        message: 'Invalid app config payload',
        errors: parsed.error.issues.map((issue) => ({
          path: issue.path.join('.'),
          message: issue.message,
        })),
      });
    }
    const config = parsed.data;
    const previous = this.requireMetadata();
    const now = new Date();
    const nextVersion = input.expectedVersion + 1;
    const event = this.audit.create(
      {
        actorId: input.actorId,
        action: 'config_update',
        targetType: 'app-config',
        targetId: 'mobile-bootstrap',
        reason: input.reason,
        requestId: input.requestId,
        summary: {
          status: 'active',
          databaseVersionBefore: previous.databaseVersion,
          databaseVersionAfter: nextVersion,
          configVersion: config.configVersion,
        },
      },
      now,
    );
    await this.database.transaction(async (connection) => {
      const [result] = await connection.execute<ResultSetHeader>(
        `UPDATE app_configs
         SET config_value=?, version=version+1, updated_by=?, updated_at=?
         WHERE config_key=? AND version=?`,
        [
          JSON.stringify(config),
          input.actorId,
          now,
          'mobile-bootstrap',
          input.expectedVersion,
        ],
      );
      if (result.affectedRows !== 1) {
        throw new ConflictException(
          'App config changed since it was loaded; refresh and retry',
        );
      }
      await this.audit.recordInTransaction(connection, event);
    });
    this.config = config;
    this.metadata = {
      databaseVersion: nextVersion,
      updatedBy: input.actorId,
      updatedAt: now.toISOString(),
    };
    this.audit.commit(event);
    return this.adminView();
  }

  private requireConfig(): ManagedAppConfig {
    if (!this.config) throw new Error('App config is not initialized');
    return this.config;
  }

  private requireMetadata(): AppConfigMetadata {
    if (!this.metadata)
      throw new Error('App config metadata is not initialized');
    return this.metadata;
  }

  private parse(value: string | ManagedAppConfig): ManagedAppConfig {
    const raw: unknown = typeof value === 'string' ? JSON.parse(value) : value;
    const parsed = managedAppConfigSchema.safeParse(raw);
    if (!parsed.success) throw new Error('Stored app config is invalid');
    return parsed.data;
  }

  private mapMetadata(row: ConfigRow): AppConfigMetadata {
    return {
      databaseVersion: row.version,
      updatedBy: row.updated_by,
      updatedAt: new Date(row.updated_at).toISOString(),
    };
  }
  private initialConfig(): ManagedAppConfig {
    return {
      configVersion: '2026.08.24.1',
      ttlSeconds: 300,
      localization: {
        fallbackLocale: 'zh-CN',
        supportedLocales: ['zh-CN', 'en-US'],
        messagesVersion: MESSAGES_VERSION,
        messages,
      },
      theme: {
        defaultMode: 'system',
        allowUserOverride: true,
        paletteVersion: PALETTE_VERSION,
        light: palettes.light,
        dark: palettes.dark,
      },
      features: {
        updateCenter: true,
        otaEnabled: true,
        directUpdateEnabled: true,
        diagnosticsEnabled: true,
      },
      updatePolicy: {
        minSupportedVersion: MIN_SUPPORTED_VERSION,
        latestVersion: LATEST_VERSION,
        otaChannel: 'production',
      },
      support: { statusPageUrl: 'https://status.example.com' },
    };
  }
}
