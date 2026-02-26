import app from './app/app.js';
import MongoDBConnection from './connections/mongodb.connection.js';
import logger from './config/logger.config.js';

logger.info(
  {
    event: 'server_started',
    env: process.env.NODE_ENV,
    version: process.env.npm_package_version,
  },
  '[SERVER] Running and healthy',
);

const startServer = async () => {
  try {
    await MongoDBConnection.getConnection();
    logger.info(
      { event: 'database_connected' },
      '[DATABASE] Successfully connected to database',
    );

  } catch (err) {
    logger.fatal(
      { event: 'server_start_failed', err },
      '[SERVER] Critical failure while starting',
    );
  }
};

await startServer();

export default app;