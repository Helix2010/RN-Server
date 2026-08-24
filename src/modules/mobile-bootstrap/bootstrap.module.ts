import { Module } from '@nestjs/common';
import { BootstrapController } from './bootstrap.controller';
import { BootstrapService } from './bootstrap.service';
import { AppReleaseModule } from '../app-release/app-release.module';
import { AppConfigModule } from '../app-config/app-config.module';

@Module({
  imports: [AppReleaseModule, AppConfigModule],
  controllers: [BootstrapController],
  providers: [BootstrapService],
  exports: [BootstrapService],
})
export class BootstrapModule {}
