import { Injectable, Optional } from '@nestjs/common';
import { coerce, lt, valid } from 'semver';
import { getEnvironment } from '../../platform/config/env';
import type {
  AppPlatform,
  BootstrapContext,
  BootstrapResponse,
  DistributionChannel,
  SupportedLocale,
  UpdateDecision,
} from './bootstrap.types';
import {
  CONFIG_VERSION,
  LATEST_VERSION,
  MESSAGES_VERSION,
  MIN_SUPPORTED_VERSION,
  PALETTE_VERSION,
  messages,
  palettes,
} from './foundation-config';
import { AppReleaseService } from '../app-release/app-release.service';
import { AppConfigService } from '../app-config/app-config.service';

@Injectable()
export class BootstrapService {
  constructor(
    @Optional() private readonly releaseService?: AppReleaseService,
    @Optional() private readonly appConfigService?: AppConfigService,
  ) {}

  create(context: BootstrapContext): BootstrapResponse {
    const environment = getEnvironment();
    const managed = this.appConfigService?.get();
    const platform = this.platform(context.platform);
    const distribution = this.distribution(context.distribution);
    const locale = this.locale(context.locale);
    const version = this.version(context.appVersion);
    const activeRelease = this.releaseService?.current(platform, distribution);
    const actionUrl =
      activeRelease?.artifact?.downloadUrl ??
      this.actionUrl(platform, distribution);
    const latestVersion =
      activeRelease?.version ??
      managed?.updatePolicy.latestVersion ??
      LATEST_VERSION;
    const minSupportedVersion =
      managed?.updatePolicy.minSupportedVersion ?? MIN_SUPPORTED_VERSION;
    const decision = this.decision(
      version,
      actionUrl,
      latestVersion,
      minSupportedVersion,
    );
    const runtimeVersion = context.runtimeVersion?.trim() || 'embedded';

    return {
      schemaVersion: 1,
      configVersion: managed?.configVersion ?? CONFIG_VERSION,
      generatedAt: new Date().toISOString(),
      ttlSeconds: managed?.ttlSeconds ?? 300,
      requestId: context.requestId,
      localization: {
        selectedLocale: locale,
        fallbackLocale: managed?.localization.fallbackLocale ?? 'zh-CN',
        supportedLocales: managed?.localization.supportedLocales ?? [
          'zh-CN',
          'en-US',
        ],
        messagesVersion:
          managed?.localization.messagesVersion ?? MESSAGES_VERSION,
        messages: managed?.localization.messages[locale] ?? messages[locale],
      },
      theme: {
        defaultMode: managed?.theme.defaultMode ?? 'system',
        allowUserOverride: managed?.theme.allowUserOverride ?? true,
        paletteVersion: managed?.theme.paletteVersion ?? PALETTE_VERSION,
        light: managed?.theme.light ?? palettes.light,
        dark: managed?.theme.dark ?? palettes.dark,
      },
      features: {
        updateCenter: managed?.features.updateCenter ?? true,
        otaEnabled: managed?.features.otaEnabled ?? true,
        directUpdateEnabled:
          platform === 'android' &&
          (managed?.features.directUpdateEnabled ?? true),
        diagnosticsEnabled: managed?.features.diagnosticsEnabled ?? true,
      },
      app: {
        version,
        buildNumber: context.buildNumber?.trim() || '0',
        platform,
        distribution,
        runtimeVersion,
      },
      update: {
        decision,
        minSupportedVersion,
        latestVersion,
        releaseNotes: activeRelease?.releaseNotes ?? [
          '远程语言与主题配置',
          '统一 OTA、商店、Direct 与 MDM 升级决策',
          '完善错误恢复和诊断信息',
        ],
        ota: {
          enabled: managed?.features.otaEnabled ?? true,
          channel: managed?.updatePolicy.otaChannel ?? environment.OTA_CHANNEL,
          runtimeVersion,
        },
        full: {
          channel: distribution,
          actionUrl,
          artifactId:
            activeRelease?.artifact?.id ??
            (actionUrl
              ? `${platform}-${distribution}-${LATEST_VERSION}`
              : null),
          sha256: activeRelease?.artifact?.sha256 ?? null,
          size: activeRelease?.artifact?.size ?? null,
        },
      },
      support: {
        diagnosticId: context.requestId,
        statusPageUrl:
          managed?.support.statusPageUrl ?? 'https://status.example.com',
      },
    };
  }

  private version(input?: string): string {
    const parsed = input ? (valid(input) ?? coerce(input)?.version) : undefined;
    return parsed ?? '1.0.0';
  }

  private platform(input?: string): AppPlatform {
    return input?.toLowerCase() === 'ios' ? 'ios' : 'android';
  }

  private distribution(input?: string): DistributionChannel {
    if (input === 'store' || input === 'direct' || input === 'mdm') {
      return input;
    }
    return 'development';
  }

  private locale(input?: string): SupportedLocale {
    return input?.toLowerCase().startsWith('en') ? 'en-US' : 'zh-CN';
  }

  private decision(
    version: string,
    actionUrl: string | null,
    latestVersion: string,
    minSupportedVersion: string,
  ): UpdateDecision {
    if (lt(version, minSupportedVersion)) {
      return actionUrl ? 'required' : 'recommended';
    }
    return lt(version, latestVersion) ? 'recommended' : 'none';
  }

  private actionUrl(
    platform: AppPlatform,
    distribution: DistributionChannel,
  ): string | null {
    const environment = getEnvironment();
    if (platform === 'android' && distribution === 'direct') {
      return environment.ANDROID_DIRECT_URL ?? null;
    }
    if (platform === 'android' && distribution === 'store') {
      return environment.ANDROID_STORE_URL ?? null;
    }
    if (platform === 'ios' && distribution === 'mdm') {
      return environment.IOS_MDM_URL ?? null;
    }
    if (platform === 'ios' && distribution === 'store') {
      return environment.IOS_STORE_URL ?? null;
    }
    return null;
  }
}
