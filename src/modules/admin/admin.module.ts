import { Module } from '@nestjs/common';
import { AppReleaseModule } from '../app-release/app-release.module';
import { AdminController } from './admin.controller';
import { AdminAuthGuard } from './admin-auth.guard';
import { AppConfigModule } from '../app-config/app-config.module';
import { AdminAuthController } from './admin-auth.controller';
import { AdminSessionService } from './admin-session.service';

@Module({
  imports: [AppReleaseModule, AppConfigModule],
  controllers: [AdminAuthController, AdminController],
  providers: [AdminAuthGuard, AdminSessionService],
})
export class AdminModule {}
