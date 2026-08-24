import { Module } from '@nestjs/common';
import { AppConfigService } from './app-config.service';
import { AuditModule } from '../audit/audit.module';

@Module({
  imports: [AuditModule],
  providers: [AppConfigService],
  exports: [AppConfigService],
})
export class AppConfigModule {}
