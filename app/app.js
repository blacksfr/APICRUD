import express from 'express';
import helmet from 'helmet';
import timeout from 'connect-timeout';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import router from '../router/UserRouter.js';

const app = express();

app.set('trust proxy', 1);

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: process.env.NODE_ENV === 'production' || process.env.NODE_ENV === 'test' ? 300 : 10000,
  message: {
    error: "TOO_MANY_REQUESTS",
    message: "Please wait 15 minutes before trying again"
  },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(helmet());
app.use(timeout('30s'));
app.use(cookieParser(process.env.COOKIE_SECRET));
app.use(express.json({ limit: '1mb' }));
app.use(limiter);

app.use((req, res, next) => {
  if (!req.timedout) next();
});

app.use(router);

app.use((req, res) => {
  res.status(404).json({
    error: "NOT_FOUND",
    message: `The route [${req.method}] ${req.url} does not exist`
  });
});

app.use((err, req, res, next) => {
  if (err.timeout || req.timedout) {
    return res.status(503).json({ 
      error: "SERVICE_UNAVAILABLE", 
      message: "The server took too long to respond"
    });
  }

  if (err.type === 'entity.too.large') {
    return res.status(413).json({ 
      error: "PAYLOAD_TOO_LARGE", 
      message: "Maximum limit is 1MB"
    });
  }

  console.error(`[SERVER_ERROR]: ${err.message}`);
  if (process.env.NODE_ENV !== 'production') console.error(err.stack);

  res.status(500).json({ error: "INTERNAL_SERVER_ERROR", message: "An unexpected error occurred" });
});

export default app;