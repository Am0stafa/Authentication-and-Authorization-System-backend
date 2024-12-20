import { Details } from 'express-useragent';

declare global {
  namespace Express {
    interface Request {
      user?: {
        userId: string;
        email: string;
        firstName: string;
        lastName: string;
      };
      useragent?: Details;
      clientIp?: string;
    }
  }
}

export {}; 