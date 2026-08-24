import { Module } from '@nestjs/common';
import { HealthModule } from './modules/health/health.module';
import { BootstrapModule } from './modules/mobile-bootstrap/bootstrap.module';
import { AdminModule } from './modules/admin/admin.module';
import { DatabaseModule } from './platform/database/database.module';

@Module({
  imports: [DatabaseModule, HealthModule, BootstrapModule, AdminModule],
})
export class AppModule {}
