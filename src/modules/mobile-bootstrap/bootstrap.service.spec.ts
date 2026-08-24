import { BootstrapService } from './bootstrap.service';

describe('BootstrapService', () => {
  const service = new BootstrapService();

  it('selects English messages and recommends an update for an older version', () => {
    const response = service.create({
      appVersion: '1.0.0',
      buildNumber: '1',
      platform: 'ios',
      distribution: 'development',
      runtimeVersion: 'runtime-1',
      locale: 'en-US',
      requestId: 'request-test',
    });

    expect(response.localization.selectedLocale).toBe('en-US');
    expect(response.localization.messages['home.title']).toBe(
      'Remote configuration center',
    );
    expect(response.update.decision).toBe('recommended');
    expect(response.theme.light.primary).toMatch(/^#[0-9A-F]{6}$/i);
  });

  it('never requires an unavailable full-update channel', () => {
    const response = service.create({
      appVersion: '0.1.0',
      platform: 'android',
      distribution: 'development',
      requestId: 'request-test',
    });

    expect(response.update.full.actionUrl).toBeNull();
    expect(response.update.decision).toBe('recommended');
  });
});
