import * as Joi from 'joi';

export const validateConfig = Joi.object({
  // Server Configuration
  PORT: Joi.number().optional(),
  API_URL: Joi.string().allow('').optional(),
  NODE_ENV: Joi.string()
    .valid('development', 'production', 'test')
    .default('development'),
  LOG_SLOW_QUERIES: Joi.boolean().truthy('true').falsy('false').optional(),
  API_DOC_URL: Joi.string().allow('').optional(),

  // Database Configuration
  DATABASE_URL: Joi.string()
    .uri()
    .required()
    .error(new Error('DATABASE_URL is missing or invalid')),

  // Account Enforcement
  ENFORCE_ACCOUNT_ACTIVE_CHECK: Joi.string()
    .valid('true', 'false')
    .default('false')
    .error(new Error('ENFORCE_ACCOUNT_ACTIVE_CHECK must be true or false')),

  // CORS
  ALLOWED_ORIGINS: Joi.string()
    .required()
    .error(new Error('ALLOWED_ORIGINS is missing')),

  // JWT Configuration
  JWT_SECRET: Joi.string().required().error(new Error('JWT_SECRET is missing')),
  RT_SECRET: Joi.string().required().error(new Error('RT_SECRET is missing')),

  // OTP Service
  TEST_OTP_PRODUCTION: Joi.string()
    .valid('true', 'false')
    .required()
    .error(new Error('TEST_OTP_PRODUCTION is missing or invalid')),

  // Redis Configuration
  REDIS_HOST: Joi.string().required().error(new Error('REDIS_HOST is missing')),
  REDIS_PORT: Joi.number().required().error(new Error('REDIS_PORT is missing')),

  // Email Service
  RESEND_API_KEY: Joi.string()
    .required()
    .error(new Error('RESEND_API_KEY is missing')),
  MAIN_EMAIL_ADDRESS: Joi.string()
    .email()
    .required()
    .error(new Error('MAIN_EMAIL_ADDRESS is missing or invalid')),
  // Google Auth
  GOOGLE_CLIENT_ID: Joi.string()
    .required()
    .error(new Error('GOOGLE_CLIENT_ID is missing')),
  GOOGLE_CLIENT_SECRET: Joi.string()
    .required()
    .error(new Error('GOOGLE_CLIENT_SECRET is missing')),
  GOOGLE_CALLBACK_URL: Joi.string()
    .uri()
    .required()
    .error(new Error('GOOGLE_CALLBACK_URL is missing or invalid')),

  // Frontend URL
  FRONTEND_URL: Joi.string()
    .uri()
    .required()
    .error(new Error('FRONTEND_URL is missing or invalid')),
});
