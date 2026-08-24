import { getEnvironment } from './platform/config/env';
import { createApp } from './create-app';

async function bootstrap(): Promise<void> {
  const environment = getEnvironment();
  const app = await createApp();
  await app.listen(environment.PORT, '0.0.0.0');
}

void bootstrap();
