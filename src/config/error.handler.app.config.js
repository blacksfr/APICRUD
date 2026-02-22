import jwt from 'jsonwebtoken';
import { ZodError } from 'zod';
import { invalidCsrfTokenError } from './csrf.config.js';
import { isProd } from './env.js';
import InvalidIDFormatError from '../errors/validation.error.js';
import InvalidPasswordFormatHashingError from '../errors/invalid.password.format.hashing.error.js';
import { badRequest, forbidden, payloadTooLarge, serviceUnavailable, internal_server_error, zodErrorProcess } from '../utils/response.util.js';

const { JsonWebTokenError, TokenExpiredError } = jwt;

export default (err, req, res, next) => {
  try{
  if (err === invalidCsrfTokenError) {
    return forbidden(res, 'Form tampered with or invalid CSRF token');
  }
  if (err.timeout || req.timedout) {
    return serviceUnavailable(res);
  }
  if (err.type === 'entity.too.large') {
    return payloadTooLarge(res);
  }
  if (err instanceof TokenExpiredError) { //Error sub
    return forbidden(res, 'Token expired. Please refresh');
  }
  if (err instanceof JsonWebTokenError) { //Error Main 
    return forbidden(res, 'Invalid token');
  }
  if (err instanceof ZodError) {
    return zodErrorProcess(res, err);
  }
  if (err instanceof InvalidIDFormatError) {
    return badRequest(res, err.message);
  }
  if (err instanceof InvalidPasswordFormatHashingError) {
  console.error(`[CORRUPTED_HASH ${req.method} ${req.url}]:`, err.message);
  return internal_server_error(res);
  }

  console.error(`[SERVER_ERROR] ${req.method} ${req.url}: ${err.message}`);
  if (!isProd) console.error(err.stack);

  return internal_server_error(res);
}catch(err){
  return internal_server_error(res);
}
};