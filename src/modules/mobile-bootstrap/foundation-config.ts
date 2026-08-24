import type { SemanticPalette, SupportedLocale } from './bootstrap.types';

export const CONFIG_VERSION = '2026.08.21.1';
export const MESSAGES_VERSION = '2026.08.21.1';
export const PALETTE_VERSION = 'ocean-1';
export const MIN_SUPPORTED_VERSION = '0.9.0';
export const LATEST_VERSION = '1.1.0';

export const palettes: Record<'light' | 'dark', SemanticPalette> = {
  light: {
    primary: '#3157D5',
    onPrimary: '#FFFFFF',
    background: '#F4F7FB',
    surface: '#FFFFFF',
    surfaceVariant: '#EAF0F8',
    text: '#101828',
    textMuted: '#5A687C',
    border: '#D5DDE9',
    success: '#147A50',
    warning: '#9A5C00',
    danger: '#B42318',
    info: '#2962A3',
    pricePositive: '#0E8A5F',
    priceNegative: '#D03C45',
    risk: '#7A4D00',
    focus: '#7293FF',
    backdrop: 'rgba(11, 18, 32, 0.56)',
  },
  dark: {
    primary: '#AFC6FF',
    onPrimary: '#082B78',
    background: '#0B1220',
    surface: '#121C2D',
    surfaceVariant: '#1D2A3E',
    text: '#F0F4FA',
    textMuted: '#A9B7CA',
    border: '#35445A',
    success: '#61D6A3',
    warning: '#F4BD68',
    danger: '#FFB4AB',
    info: '#A8CAFF',
    pricePositive: '#5CDBA8',
    priceNegative: '#FF7B86',
    risk: '#F4BD68',
    focus: '#AFC6FF',
    backdrop: 'rgba(0, 0, 0, 0.72)',
  },
};

const zhCN: Record<string, string> = {
  'app.name': 'RN 应用基座',
  'home.eyebrow': 'FOUNDATION / 参考功能',
  'home.title': '远程配置中心',
  'home.description': '一个真实接口同时驱动语言、主题、功能开关与升级策略。',
  'home.remoteConfig': '远程配置',
  'home.theme': '主题偏好',
  'home.language': '语言',
  'home.update': '应用升级',
  'home.features': '能力开关',
  'action.refresh': '刷新配置',
  'action.retry': '重新加载',
  'action.checkUpdate': '检查更新',
  'action.install': '前往更新',
  'theme.system': '跟随系统',
  'theme.light': '浅色',
  'theme.dark': '深色',
  'status.connected': '服务已连接',
  'status.cached': '正在使用安全缓存',
  'status.loading': '正在同步应用配置',
  'status.error': '暂时无法获取远程配置',
  'update.none': '当前已经是最新版本',
  'update.optional': '发现可选更新',
  'update.recommended': '建议升级到最新版本',
  'update.required': '当前版本必须升级后继续使用',
};

const enUS: Record<string, string> = {
  'app.name': 'RN App Foundation',
  'home.eyebrow': 'FOUNDATION / REFERENCE FEATURE',
  'home.title': 'Remote configuration center',
  'home.description':
    'One real endpoint drives locale, theme, feature flags, and updates.',
  'home.remoteConfig': 'Remote configuration',
  'home.theme': 'Theme preference',
  'home.language': 'Language',
  'home.update': 'App updates',
  'home.features': 'Feature flags',
  'action.refresh': 'Refresh configuration',
  'action.retry': 'Try again',
  'action.checkUpdate': 'Check for updates',
  'action.install': 'Open update',
  'theme.system': 'System',
  'theme.light': 'Light',
  'theme.dark': 'Dark',
  'status.connected': 'Service connected',
  'status.cached': 'Using safe cached configuration',
  'status.loading': 'Syncing app configuration',
  'status.error': 'Remote configuration is temporarily unavailable',
  'update.none': 'You already have the latest version',
  'update.optional': 'An optional update is available',
  'update.recommended': 'Updating to the latest version is recommended',
  'update.required': 'Update is required to continue',
};

export const messages: Record<SupportedLocale, Record<string, string>> = {
  'zh-CN': zhCN,
  'en-US': enUS,
};
