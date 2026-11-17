import 'dotenv/config';
import { z } from 'zod';

const schema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().default(8080),
  CORS_ORIGINS: z.string().default(''),
  DATABASE_URL: z.string().min(1),
  SUPABASE_URL: z.string().url(),
  SUPABASE_SERVICE_ROLE_KEY: z.string().min(1),
  SUPABASE_JWT_SECRET: z.string().min(1),
  QR_HMAC_SECRET: z.string().min(32),
  TAG_SIGNING_SECRET: z.string().min(32),
  PII_ENCRYPTION_KEY: z.string().refine((v) => Buffer.from(v, 'base64').length === 32, 'must be 32 bytes base64'),
  PII_HASH_KEY: z.string().min(32),
  REQUIRE_ADMIN_MFA: z.enum(['true', 'false']).default('true').transform((v) => v === 'true'),
  R2_ACCOUNT_ID: z.string().optional(),
  R2_ACCESS_KEY_ID: z.string().optional(),
  R2_SECRET_ACCESS_KEY: z.string().optional(),
  R2_BUCKET: z.string().optional(),
  R2_PUBLIC_BASE_URL: z.string().url().optional(),
});

export const env = schema.parse(process.env); // fail fast on boot
