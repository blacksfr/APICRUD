import express from 'express';
import helmet from 'helmet';
import timeout from 'connect-timeout';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import routes from '../routes/user.route.js';
import corsConfig from '../config/cors.config.js';
import notfoundHandlerConfig from '../config/notfound.handler.config.js';
import timeoutHandlerConfig from '../config/timeout.handler.config.js';
import errorHandlerAppConfig from '../config/error.handler.app.config.js';
import ratelimitglobalConfig from '../config/ratelimit.global.config.js';
import helmetConfig from '../config/helmet.config.js';
import { COOKIE_SECRET } from '../config/env.js';
import { doubleCsrfProtection } from '../config/csrf.config.js';

const app = express();

app.set('trust proxy', 1);

app.use(timeout('30s'));

app.use(helmet(helmetConfig));

app.use(cors(corsConfig));

app.use(ratelimitglobalConfig);

app.use(express.json({ limit: '1mb' }));

app.use(cookieParser(COOKIE_SECRET));

app.use(doubleCsrfProtection);

app.use(timeoutHandlerConfig);

app.use(routes);

app.use(notfoundHandlerConfig);

app.use(errorHandlerAppConfig);

export default app;