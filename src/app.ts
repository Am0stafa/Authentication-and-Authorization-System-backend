import compression from 'compression';
import path from 'path';
import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import { ApplicationError } from './errors/application-error';
import { router } from './routes';
import useragent from 'express-useragent';
import requestIp from 'request-ip';

export const app = express();

app.use(cors({
  origin: process.env.NODE_ENV === 'production'
    ? ['https://yourdomain.com', 'https://app.yourdomain.com']
    : '*',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  maxAge: 86400
}));

app.use(compression());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.set('port', process.env.PORT || 8080);

app.use(express.static(path.join(__dirname, 'public'), { maxAge: 31557600000 }));

app.use(useragent.express());
app.use(requestIp.mw());

app.set('trust proxy', true);

app.use('/api/v1', router);

app.use((err: ApplicationError, req: Request, res: Response, next: NextFunction) => {
  if (res.headersSent) {
    return next(err);
  }

  return res.status(err.status || 500).json({
    error: process.env.NODE_ENV === 'development' ? err : undefined,
    message: err.message
  });
});
