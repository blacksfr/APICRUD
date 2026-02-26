import jwt from 'jsonwebtoken';
import { ZodError } from 'zod';
import { invalidCsrfTokenError} from './csrf.config.js';
import logger from './logger.config.js';
import MissingSessionError from '../errors/missing.sid.error.js';
import InvalidIDFormatError from '../errors/validation.error.js';
import InvalidPasswordFormatHashingError from '../errors/invalid.password.format.hashing.error.js';
import EncryptionError from '../errors/encrypt.error.js';
import DecryptionError from '../errors/decrypt.error.js';
import {
  badRequest,
  forbidden,
  payloadTooLarge,
  serviceUnavailable,
  internal_server_error,
  zodErrorProcess,
} from '../utils/response.util.js';

const { JsonWebTokenError, TokenExpiredError } = jwt;

export default (err, req, res, next) => {
  try {
    if (err === invalidCsrfTokenError) {
      logger.warn(
        { event: 'csrf_token_invalid', requestId: req.id, method: req.method, url: req.url },
        '[ErrorHandler] Invalid or tampered CSRF token',
      );
      return forbidden(res, 'Form tampered with or invalid CSRF token');
    }

    if (err instanceof MissingSessionError) {
      logger.warn(
        { event: 'session_missing', requestId: req.id, method: req.method, url: req.url },
        '[ErrorHandler] Request missing session identifier',
      );
      return badRequest(res, 'Session expired or missing. Please refresh the page');
    }

    if (err.timeout || req.timedout) {
      logger.warn(
        { event: 'request_timeout', requestId: req.id, method: req.method, url: req.url },
        '[ErrorHandler] Request timed out',
      );
      return serviceUnavailable(res);
    }

    if (err.type === 'entity.too.large') {
      logger.warn(
        { event: 'payload_too_large', requestId: req.id, method: req.method, url: req.url },
        '[ErrorHandler] Request payload too large',
      );
      return payloadTooLarge(res);
    }

    if (err.type === 'entity.parse.failed') {
      logger.warn(
        { event: 'invalid_json_body', requestId: req.id, method: req.method, url: req.url },
        '[ErrorHandler] Invalid JSON in request body',
      );
      return badRequest(res, 'Invalid JSON in request body');
    }

    if (err instanceof TokenExpiredError) {
      logger.info(
        { event: 'token_expired', requestId: req.id, method: req.method, url: req.url },
        '[ErrorHandler] Access token expired',
      );
      return forbidden(res, 'Token expired. Please refresh');
    }

    if (err instanceof JsonWebTokenError) {
      logger.warn(
        { event: 'token_invalid', requestId: req.id, method: req.method, url: req.url },
        '[ErrorHandler] Invalid JWT',
      );
      return forbidden(res, 'Invalid token');
    }

    if (err instanceof ZodError) {
      logger.info(
        { event: 'validation_failed', requestId: req.id, method: req.method, url: req.url, issues: err.issues },
        '[ErrorHandler] Request validation failed',
      );
      return zodErrorProcess(res, err);
    }

    if (err instanceof InvalidIDFormatError) {
      logger.info(
        { event: 'invalid_id_format', requestId: req.id, method: req.method, url: req.url },
        '[ErrorHandler] Invalid MongoDB ID format',
      );
      return badRequest(res, err.message);
    }

    if (err instanceof InvalidPasswordFormatHashingError) {
      logger.error(
        { event: 'corrupted_hash', requestId: req.id, method: req.method, url: req.url, err },
        '[ErrorHandler] Corrupted password hash detected',
      );
      return internal_server_error(res);
    }

    if (err instanceof EncryptionError) {
      logger.error(
        { event: 'encryption_failure', requestId: req.id, method: req.method, url: req.url, err },
        '[ErrorHandler] Encryption failure',
      );
      return internal_server_error(res);
    }

    if (err instanceof DecryptionError) {
      logger.error(
        { event: 'decryption_failure', requestId: req.id, method: req.method, url: req.url, err },
        '[ErrorHandler] Decryption failure',
      );
      return internal_server_error(res);
    }

    logger.error(
      { event: 'unhandled_error', requestId: req.id, method: req.method, url: req.url, err },
      '[ErrorHandler] Unhandled internal server error',
    );
    return internal_server_error(res);
  } catch {
    return internal_server_error(res);
  }
};