import {
  Body,
  Controller,
  Get,
  HttpCode,
  Post,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import {
  ApiBody,
  ApiCookieAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { AdminAuthGuard } from './admin-auth.guard';
import {
  type AdminRequestContext,
  AdminSessionService,
} from './admin-session.service';

const loginSchema = z.object({
  username: z.string().trim().min(1).max(120),
  password: z.string().min(1).max(1024),
});

@ApiTags('admin-auth')
@Controller('v1/admin/auth')
export class AdminAuthController {
  constructor(private readonly sessions: AdminSessionService) {}

  @Post('login')
  @HttpCode(200)
  @ApiOperation({ summary: 'Create an administrator browser session' })
  @ApiBody({
    schema: {
      type: 'object',
      required: ['username', 'password'],
      properties: {
        username: { type: 'string', maxLength: 120 },
        password: { type: 'string', format: 'password', maxLength: 1024 },
      },
    },
  })
  @ApiResponse({ status: 200, description: 'Authenticated session' })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  @ApiResponse({ status: 429, description: 'Too many attempts' })
  async login(
    @Body() body: unknown,
    @Req() request: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ) {
    const parsed = loginSchema.safeParse(body);
    if (!parsed.success) {
      throw new UnauthorizedException('Invalid username or password');
    }
    const result = await this.sessions.login(
      parsed.data.username,
      parsed.data.password,
      request.ip,
    );
    reply.header('set-cookie', this.sessions.cookie(result.token));
    reply.header('cache-control', 'no-store');
    return { authenticated: true, ...result.principal };
  }

  @Get('session')
  @UseGuards(AdminAuthGuard)
  @ApiCookieAuth('rn_admin_session')
  @ApiOperation({ summary: 'Read the current administrator session' })
  session(@Req() request: FastifyRequest & AdminRequestContext) {
    return { authenticated: true, ...request.adminPrincipal };
  }

  @Post('logout')
  @HttpCode(200)
  @UseGuards(AdminAuthGuard)
  @ApiCookieAuth('rn_admin_session')
  @ApiOperation({ summary: 'Revoke the current administrator session' })
  async logout(
    @Req() request: FastifyRequest,
    @Res({ passthrough: true }) reply: FastifyReply,
  ) {
    await this.sessions.logout(request.headers.cookie);
    reply.header('set-cookie', this.sessions.clearCookie());
    reply.header('cache-control', 'no-store');
    return { authenticated: false };
  }
}
