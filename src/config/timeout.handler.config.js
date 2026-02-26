import logger from './logger.config.js';
import { serviceUnavailable } from '../utils/response.util.js';

export default (req, res, next) => {
  if (req.timedout) {
    logger.warn(
      { event: 'request_timeout', requestId: req.id, method: req.method, url: req.url },
      '[TimeoutHandler] Request timed out before reaching handler',
    );
    return serviceUnavailable(res);
  }
  next();
};