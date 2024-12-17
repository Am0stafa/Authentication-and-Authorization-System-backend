import { RequestHandler } from 'express';
import { requestHandler } from '../../middleware/request-middleware';
import { revokeRefreshToken } from '../../utils/refreshToken';

const logoutWrapper: RequestHandler = async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (refreshToken) {
    // Revoke the refresh token if it exists
    await revokeRefreshToken(req.user.userId, refreshToken);
  }

  // Clear both access and refresh token cookies
  res.cookie('refreshToken', '', {
    httpOnly: true,
    sameSite: 'lax',
    expires: new Date(0),
    path: '/'
  });

  return res.status(200).json({
    success: true,
    message: 'Logged out successfully'
  });
};

export const logout = requestHandler(logoutWrapper, {
  skipJwtAuth: false
}); 