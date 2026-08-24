import { Module } from '@nestjs/common';
import { AppReleaseRepository } from './app-release.repository';
import { AppReleaseService } from './app-release.service';
import { AuditModule } from '../audit/audit.module';

@Module({
  imports: [AuditModule],
  providers: [AppReleaseRepository, AppReleaseService],
  exports: [AppReleaseService],
})
export class AppReleaseModule {}
