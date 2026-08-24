import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';

type ProblemDetails = {
  type: string;
  title: string;
  status: number;
  code: string;
  requestId: string;
};

@Catch()
export class ProblemDetailsFilter implements ExceptionFilter {
  private readonly logger = new Logger(ProblemDetailsFilter.name);

  catch(exception: unknown, host: ArgumentsHost): void {
    const context = host.switchToHttp();
    const request = context.getRequest<FastifyRequest>();
    const reply = context.getResponse<FastifyReply>();
    const status =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;
    const code = status >= 500 ? 'INTERNAL_ERROR' : 'REQUEST_REJECTED';

    if (status >= 500) {
      const error = exception instanceof Error ? exception : undefined;
      this.logger.error(
        `Unhandled request failure requestId=${request.id}`,
        error?.stack,
      );
    }

    const problem: ProblemDetails = {
      type: `https://rn-foundation.local/problems/${code.toLowerCase()}`,
      title:
        status >= 500
          ? 'The service could not complete the request'
          : 'Request rejected',
      status,
      code,
      requestId: request.id,
    };

    void reply
      .status(status)
      .header('content-type', 'application/problem+json')
      .send(problem);
  }
}
