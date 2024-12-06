import { RequestHandler } from 'express';
import { requestHandler } from '../../middleware/request-middleware';

const logoutWrapper: RequestHandler = async (req, res) => {
  // Clear the JWT cookie
  res.cookie('token', '', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    expires: new Date(0), // Set expiration to past date to ensure deletion
    path: '/',
  });

  return res.status(200).json({
    success: true,
    message: 'Logged out successfully'
  });
};

export const logout = requestHandler(logoutWrapper, {
  skipJwtAuth: false // Require authentication to logout
}); 