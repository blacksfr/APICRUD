import jwt from 'jsonwebtoken';
import { ZodError } from 'zod';
import { invalidCsrfTokenError } from './csrf.config.js';
import logger from './logger.config.js';
import InvalidIDFormatError from '../errors/validation.error.js';
import InvalidPasswordFormatHashingError from '../errors/invalid.password.format.hashing.error.js';
import EncryptionError from '../errors/encrypt.error.js';
import DecryptionError from '../errors/decrypt.error.js';
import { badRequest, forbidden, payloadTooLarge, serviceUnavailable, internal_server_error, zodErrorProcess } from '../utils/response.util.js';

const { JsonWebTokenError, TokenExpiredError } = jwt;

export default (err, req, res, next) => {
  try {
    if (err === invalidCsrfTokenError) {
      return forbidden(res, 'Form tampered with or invalid CSRF token');
    }
    if (err.timeout || req.timedout) {
      return serviceUnavailable(res);
    }
    if (err.type === 'entity.too.large') {
      return payloadTooLarge(res);
    }
    if (err.type === 'entity.parse.failed') {
      return badRequest(res, 'Invalid JSON in request body');
    }
    if (err instanceof TokenExpiredError) {
      return forbidden(res, 'Token expired. Please refresh');
    }
    if (err instanceof JsonWebTokenError) {
      return forbidden(res, 'Invalid token');
    }
    if (err instanceof ZodError) {
      return zodErrorProcess(res, err);
    }
    if (err instanceof InvalidIDFormatError) {
      return badRequest(res, err.message);
    }
    if (err instanceof InvalidPasswordFormatHashingError) {
      logger.error({ err, requestId: req.id }, '[CORRUPTED_HASH]');
      return internal_server_error(res);
    }
    if (err instanceof EncryptionError) {
      logger.error({ err, requestId: req.id, method: req.method, url: req.url }, '[ENCRYPTION_FAILURE]');
      return internal_server_error(res);
    }
    if (err instanceof DecryptionError) {
      logger.error({ err, requestId: req.id, method: req.method, url: req.url }, '[DECRYPTION_FAILURE]');
      return internal_server_error(res);
    }

    logger.error({ err, requestId: req.id, method: req.method, url: req.url }, 'Unhandled server error');
    return internal_server_error(res);
  } catch {
    return internal_server_error(res);
  }
};