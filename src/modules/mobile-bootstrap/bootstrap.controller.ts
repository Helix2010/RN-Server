import { Controller, Get, Headers, Query, Req, Res } from '@nestjs/common';
import {
  ApiHeader,
  ApiOkResponse,
  ApiOperation,
  ApiQuery,
  ApiTags,
} from '@nestjs/swagger';
import { createHash } from 'node:crypto';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { BootstrapResponseDto } from './bootstrap.dto';
import { BootstrapService } from './bootstrap.service';

@ApiTags('mobile')
@Controller('v1/mobile')
export class BootstrapController {
  constructor(private readonly bootstrapService: BootstrapService) {}

  @Get('bootstrap')
  @ApiOperation({
    summary: 'Get typed mobile locale, theme, flags and update policy',
  })
  @ApiQuery({ name: 'locale', required: false, example: 'zh-CN' })
  @ApiHeader({ name: 'X-App-Version', required: false })
  @ApiHeader({ name: 'X-Build-Number', required: false })
  @ApiHeader({ name: 'X-Platform', required: false })
  @ApiHeader({ name: 'X-Distribution-Channel', required: false })
  @ApiHeader({ name: 'X-Runtime-Version', required: false })
  @ApiOkResponse({ type: BootstrapResponseDto })
  getBootstrap(
    @Req() request: FastifyRequest,
    @Res() reply: FastifyReply,
    @Query('locale') locale?: string,
    @Headers('x-app-version') appVersion?: string,
    @Headers('x-build-number') buildNumber?: string,
    @Headers('x-platform') platform?: string,
    @Headers('x-distribution-channel') distribution?: string,
    @Headers('x-runtime-version') runtimeVersion?: string,
    @Headers('if-none-match') ifNoneMatch?: string,
  ): void {
    const response = this.bootstrapService.create({
      appVersion,
      buildNumber,
      platform,
      distribution,
      runtimeVersion,
      locale,
      requestId: request.id,
    });
    const etag = `"${createHash('sha256')
      .update(
        JSON.stringify({
          ...response,
          generatedAt: undefined,
          requestId: undefined,
          support: { ...response.support, diagnosticId: undefined },
        }),
      )
      .digest('base64url')}"`;

    reply.header('etag', etag).header('cache-control', 'private, max-age=300');
    if (ifNoneMatch === etag) {
      void reply.status(304).send();
      return;
    }
    void reply.send(response);
  }
}
