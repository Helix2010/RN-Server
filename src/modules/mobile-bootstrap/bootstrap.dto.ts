import { ApiProperty } from '@nestjs/swagger';

export class BootstrapResponseDto {
  @ApiProperty({ example: 1 })
  schemaVersion!: 1;

  @ApiProperty({ example: '2026.08.21.1' })
  configVersion!: string;

  @ApiProperty({ format: 'date-time' })
  generatedAt!: string;

  @ApiProperty({ example: 300 })
  ttlSeconds!: number;

  @ApiProperty({ example: 'req-01' })
  requestId!: string;

  @ApiProperty({ type: 'object', additionalProperties: true })
  localization!: object;

  @ApiProperty({ type: 'object', additionalProperties: true })
  theme!: object;

  @ApiProperty({ type: 'object', additionalProperties: { type: 'boolean' } })
  features!: object;

  @ApiProperty({ type: 'object', additionalProperties: true })
  app!: object;

  @ApiProperty({ type: 'object', additionalProperties: true })
  update!: object;

  @ApiProperty({ type: 'object', additionalProperties: true })
  support!: object;
}
