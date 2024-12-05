import { Response } from 'express';
import jwt from 'jsonwebtoken';

interface JWTPayload {
  userId: string;
  role?: string;
}

export const generateJWTandSetCookie = (res: Response, payload: JWTPayload): string => {
  if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET is not defined in environment variables');
  }

  const token = jwt.sign(
    payload,
    process.env.JWT_SECRET,
    { 
      expiresIn: '10d',
      algorithm: 'HS256'
    }
  );

  // Set cookie with enhanced security options
  res.cookie('token', token, {
    httpOnly: true, // Prevents JavaScript access to the cookie
    secure: process.env.NODE_ENV === 'production', // HTTPS only in production
    sameSite: 'lax',
    maxAge: 10 * 24 * 60 * 60 * 1000, // 10 days
    path: '/', // Cookie is available for all paths
    // domain: process.env.COOKIE_DOMAIN || undefined, // Restrict to specific domain
  });

  return;
};