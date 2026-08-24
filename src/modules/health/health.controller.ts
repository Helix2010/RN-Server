import { Controller, Get } from '@nestjs/common';
import { ApiOkResponse, ApiTags } from '@nestjs/swagger';
import { MysqlService } from '../../platform/database/mysql.service';

@ApiTags('health')
@Controller('health')
export class HealthController {
  constructor(private readonly database: MysqlService) {}
  @Get('live')
  @ApiOkResponse({
    schema: {
      type: 'object',
      required: ['status'],
      properties: { status: { type: 'string', example: 'ok' } },
    },
  })
  live(): { status: 'ok' } {
    return { status: 'ok' };
  }

  @Get('ready')
  @ApiOkResponse({
    schema: {
      type: 'object',
      required: ['status'],
      properties: { status: { type: 'string', example: 'ready' } },
    },
  })
  async ready(): Promise<{ status: 'ready'; database: 'mysql' }> {
    await this.database.ping();
    return { status: 'ready', database: 'mysql' };
  }
}
