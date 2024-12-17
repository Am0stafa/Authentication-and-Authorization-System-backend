import { RequestHandler } from 'express';
import { requestHandler } from '../../middleware/request-middleware';
import { UnauthorizedRequest } from '../../errors';
import { verifyRefreshToken, generateRefreshToken } from '../../utils/refreshToken';
import { generateAccessToken } from '../../utils/accessToken';
import { User } from '../../models/User';

const refreshTokenWrapper: RequestHandler = async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    throw new UnauthorizedRequest('Refresh token not provided');
  }

  try {
    // Verify the refresh token
    const { userId, family, version } = await verifyRefreshToken(refreshToken);

    // Revoke the used refresh token
    await User.updateOne(
      { _id: userId, 'refreshTokens.token': refreshToken },
      { $set: { 'refreshTokens.$.isRevoked': true } }
    );

    // Generate new tokens with incremented version
    const accessToken = generateAccessToken(userId);
    const { token: newRefreshToken, expiresAt } = await generateRefreshToken(userId, {
      userAgent: req.headers['user-agent'] || 'unknown',
      ipAddress: req.ip,
      family: family,
      version: version + 1
    });

    // Set cookies
    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      sameSite: 'lax',
      expires: expiresAt,
      path: '/'
    });

    return res.json({
      success: true,
      data: {
        accessToken
      }
    });
  } catch (error) {
    if (error.message === 'Token has been revoked') {
      throw new UnauthorizedRequest('Token has been revoked due to potential security breach');
    }
    throw new UnauthorizedRequest('Invalid refresh token');
  }
};

export const refreshToken = requestHandler(refreshTokenWrapper, {
  skipJwtAuth: true
}); 