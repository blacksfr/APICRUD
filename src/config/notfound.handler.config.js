import { notFound } from '../utils/response.util.js';
import logger from './logger.config.js';

export default (req, res) => {
  logger.warn(
    { event: 'route_not_found', requestId: req.id, method: req.method, url: req.url },
    '[NotFoundHandler] Route not found',
  );
  notFound(res, `The route [${req.method}] ${req.url} does not exist`);
};