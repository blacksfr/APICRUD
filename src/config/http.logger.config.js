import pinoHttp from 'pino-http';
import crypto from 'crypto';
import logger from './logger.config.js';
import { isProd } from './env.js';

const SILENT_ROUTES = new Set([
  '/api/v1',
  '/favicon.ico',
]);

const httpLogger = pinoHttp({
  logger,
  autoLogging: {
    ignore: (req) => SILENT_ROUTES.has(req.url),
  },
  customLogLevel: (req, res, err) => {
    if (err || res.statusCode >= 500) return 'error';
    if (res.statusCode >= 400) return 'warn';
    return 'info';
  },
  customSuccessMessage: (req, res) =>
    `${req.method} ${req.url} - ${res.statusCode}`,

  customErrorMessage: (req, res, err) =>
    `${req.method} ${req.url} - ${res.statusCode} - ${err.message}`,
  customProps: (req) => ({
    requestId: req.id,
    ip: req.ip ?? req.headers['x-forwarded-for'],
  }),
  serializers: {
    req(req) {
      return {
        id: req.id,
        method: req.method,
        url: req.url,
      };
    },
    res(res) {
      return {
        statusCode: res.statusCode,
      };
    },
  },
  genReqId: (req, res) => {
    const id = req.headers['x-request-id'] ?? crypto.randomUUID();
    res.setHeader('x-request-id', id);
    return id;
  },
  ...(isProd && {
    customAttributeKeys: {
      responseTime: 'durationMs',
    },
  }),
});

export default httpLogger;