import pino from 'pino';
import { isProd } from './env.js';

const REDACTED_FIELDS = [
  'password',
  'hashedPassword',
  'token',
  'accessToken',
  'refreshToken',
  'authorization',
  'cookie',
  'email',
  'emailHmac',
  'req.remoteAddress',
  'req.headers.authorization',
  'req.headers.cookie',
  'res.headers["set-cookie"]',
];

const logger = pino({
  level: isProd ? 'info' : 'debug',
  redact: {
    paths: REDACTED_FIELDS,
    censor: '[Redacted]',
  },

  transport: isProd
    ? undefined
    : {
      target: 'pino-pretty',
      options: {
        colorize: true,
        translateTime: 'SYS:HH:MM:ss',
        ignore: 'pid,hostname,env,version',
        messageFormat: '{msg}',
      },
    },

  base: {
    env: process.env.NODE_ENV,
    version: process.env.npm_package_version,
  },

  timestamp: pino.stdTimeFunctions.isoTime,

  serializers: {
    err: pino.stdSerializers.err,
    req: pino.stdSerializers.req,
    res: pino.stdSerializers.res,
  },
});

export default logger;