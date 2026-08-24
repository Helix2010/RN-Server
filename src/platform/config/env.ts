import 'dotenv/config';
import { z } from 'zod';

const optionalUrl = z
  .string()
  .trim()
  .transform((value) => (value.length === 0 ? undefined : value))
  .pipe(z.url().optional())
  .optional();

const booleanString = (defaultValue: 'true' | 'false') =>
  z
    .enum(['true', 'false'])
    .default(defaultValue)
    .transform((value) => value === 'true');

const optionalAdminApiKey = z
  .string()
  .trim()
  .transform((value) => (value.length === 0 ? undefined : value))
  .pipe(z.string().min(16).optional())
  .optional();

const optionalPasswordHash = z
  .string()
  .trim()
  .transform((value) => (value.length === 0 ? undefined : value))
  .pipe(
    z
      .string()
      .regex(/^scrypt\$\d+\$\d+\$\d+\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+$/)
      .optional(),
  )
  .optional();

const envSchema = z
  .object({
    NODE_ENV: z
      .enum(['development', 'test', 'production'])
      .default('development'),
    PORT: z.coerce.number().int().positive().max(65535).default(3000),
    CORS_ORIGINS: z.string().default('*'),
    ANDROID_STORE_URL: optionalUrl,
    ANDROID_DIRECT_URL: optionalUrl,
    IOS_STORE_URL: optionalUrl,
    IOS_MDM_URL: optionalUrl,
    OTA_CHANNEL: z.string().min(1).default('production'),
    ADMIN_API_KEY: optionalAdminApiKey,
    ADMIN_USERNAME: z.string().trim().min(1).max(120).optional(),
    ADMIN_PASSWORD_HASH: optionalPasswordHash,
    ADMIN_SESSION_TTL_SECONDS: z.coerce
      .number()
      .int()
      .min(300)
      .max(86400)
      .default(28800),
    ADMIN_COOKIE_SECURE: booleanString('false'),
    ADMIN_LOGIN_MAX_ATTEMPTS: z.coerce.number().int().min(3).max(20).default(5),
    ADMIN_LOGIN_WINDOW_SECONDS: z.coerce
      .number()
      .int()
      .min(60)
      .max(86400)
      .default(900),
    MYSQL_HOST: z.string().min(1).default('127.0.0.1'),
    MYSQL_PORT: z.coerce.number().int().positive().max(65535).default(3306),
    MYSQL_USER: z.string().min(1).default('root'),
    MYSQL_PASSWORD: z.string().default(''),
    MYSQL_DATABASE: z
      .string()
      .regex(/^[A-Za-z0-9_]+$/)
      .default('rn_foundation'),
    MYSQL_CONNECTION_LIMIT: z.coerce
      .number()
      .int()
      .positive()
      .max(100)
      .default(10),
    MYSQL_CHARSET: z
      .string()
      .regex(/^[A-Za-z0-9_]+$/)
      .default('utf8mb4'),
    MYSQL_TIMEZONE: z
      .string()
      .regex(/^(?:Z|local|[+-](?:0\d|1\d|2[0-3]):[0-5]\d)$/)
      .default('Z'),
    MYSQL_PARSE_TIME: booleanString('true'),
  })
  .superRefine((environment, context) => {
    if (environment.NODE_ENV !== 'production') return;
    if (!environment.ADMIN_USERNAME) {
      context.addIssue({
        code: 'custom',
        path: ['ADMIN_USERNAME'],
        message: 'ADMIN_USERNAME is required in production',
      });
    }
    if (!environment.ADMIN_PASSWORD_HASH) {
      context.addIssue({
        code: 'custom',
        path: ['ADMIN_PASSWORD_HASH'],
        message: 'ADMIN_PASSWORD_HASH is required in production',
      });
    }
    if (environment.CORS_ORIGINS === '*') {
      context.addIssue({
        code: 'custom',
        path: ['CORS_ORIGINS'],
        message: 'CORS_ORIGINS must be explicit in production',
      });
    }
  });

export type Environment = z.infer<typeof envSchema>;

let cached: Environment | undefined;

export function getEnvironment(): Environment {
  cached ??= envSchema.parse(process.env);
  return cached;
}
