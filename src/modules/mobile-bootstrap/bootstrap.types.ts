export type AppPlatform = 'ios' | 'android';
export type DistributionChannel = 'store' | 'direct' | 'mdm' | 'development';
export type SupportedLocale = 'zh-CN' | 'en-US';
export type UpdateDecision = 'none' | 'optional' | 'recommended' | 'required';

export type SemanticPalette = {
  primary: string;
  onPrimary: string;
  background: string;
  surface: string;
  surfaceVariant: string;
  text: string;
  textMuted: string;
  border: string;
  success: string;
  warning: string;
  danger: string;
  info: string;
  pricePositive: string;
  priceNegative: string;
  risk: string;
  focus: string;
  backdrop: string;
};

export type BootstrapContext = {
  appVersion?: string;
  buildNumber?: string;
  platform?: string;
  distribution?: string;
  runtimeVersion?: string;
  locale?: string;
  requestId: string;
};

export type BootstrapResponse = {
  schemaVersion: 1;
  configVersion: string;
  generatedAt: string;
  ttlSeconds: number;
  requestId: string;
  localization: {
    selectedLocale: SupportedLocale;
    fallbackLocale: SupportedLocale;
    supportedLocales: SupportedLocale[];
    messagesVersion: string;
    messages: Record<string, string>;
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
  app: {
    version: string;
    buildNumber: string;
    platform: AppPlatform;
    distribution: DistributionChannel;
    runtimeVersion: string;
  };
  update: {
    decision: UpdateDecision;
    minSupportedVersion: string;
    latestVersion: string;
    releaseNotes: string[];
    ota: {
      enabled: boolean;
      channel: string;
      runtimeVersion: string;
    };
    full: {
      channel: DistributionChannel;
      actionUrl: string | null;
      artifactId: string | null;
      sha256: string | null;
      size: number | null;
    };
  };
  support: {
    diagnosticId: string;
    statusPageUrl: string;
  };
};
