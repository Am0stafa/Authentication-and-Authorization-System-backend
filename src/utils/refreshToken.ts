import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { User } from '../models/User';

interface RefreshTokenPayload {
  userId: string;
  type: 'refresh';
  family: string;
  version: number;
}

interface TokenMetadata {
  userAgent: string;
  ipAddress: string;
  family: string;
  version: number;
}

export const generateRefreshToken = async (
  userId: string, 
  metadata: TokenMetadata
): Promise<{token: string, expiresAt: Date}> => {
  if (!process.env.JWT_REFRESH_SECRET) {
    throw new Error('JWT_REFRESH_SECRET is not defined');
  }

  const family = crypto.randomBytes(32).toString('hex');
  const version = 1;
  
  const payload: RefreshTokenPayload = {
    userId,
    type: 'refresh',
    family,
    version
  };

  const token = jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {
    expiresIn: '7d',
    algorithm: 'HS256'
  });

  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  // Store with metadata and family info
  await User.findByIdAndUpdate(userId, {
    $push: {
      refreshTokens: {
        token,
        family,
        version,
        expiresAt,
        issuedAt: new Date(),
        lastUsed: new Date(),
        issuedBy: metadata.ipAddress,
        device: metadata.userAgent,
        isRevoked: false
      }
    }
  });

  return { token, expiresAt };
};

export const verifyRefreshToken = async (token: string): Promise<{userId: string, family: string, version: number}> => {
  if (!process.env.JWT_REFRESH_SECRET) {
    throw new Error('JWT_REFRESH_SECRET is not defined');
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET) as RefreshTokenPayload;
    if (decoded.type !== 'refresh') {
      throw new Error('Invalid token type');
    }

    // Check if token exists and hasn't been revoked
    const user = await User.findOne({
      _id: decoded.userId,
      'refreshTokens': {
        $elemMatch: {
          token,
          family: decoded.family,
          version: decoded.version,
          isRevoked: false,
          expiresAt: { $gt: new Date() }
        }
      }
    });

    if (!user) {
      // Potential reuse attack - revoke all tokens in the family
      await User.updateMany(
        { _id: decoded.userId, 'refreshTokens.family': decoded.family },
        { $set: { 'refreshTokens.$.isRevoked': true } }
      );
      throw new Error('Token has been revoked');
    }

    // Update last used timestamp
    await User.updateOne(
      { _id: decoded.userId, 'refreshTokens.token': token },
      { $set: { 'refreshTokens.$.lastUsed': new Date() } }
    );

    return {
      userId: decoded.userId,
      family: decoded.family,
      version: decoded.version
    };
  } catch (error) {
    if (error.message === 'Token has been revoked') {
      throw error;
    }
    throw new Error('Invalid refresh token');
  }
};

export const revokeRefreshToken = async (userId: string, token: string): Promise<void> => {
  // Find the token to get its family
  const user = await User.findOne({
    _id: userId,
    'refreshTokens.token': token
  });

  if (!user) return;

  const tokenDoc = user.refreshTokens.find(rt => rt.token === token);
  if (!tokenDoc) return;

  // Revoke all tokens in the same family
  await User.updateMany(
    { _id: userId },
    { 
      $set: {
        'refreshTokens.$[elem].isRevoked': true
      }
    },
    {
      arrayFilters: [{ 'elem.family': tokenDoc.family }]
    }
  );
};

export const revokeAllRefreshTokens = async (userId: string): Promise<void> => {
  await User.findByIdAndUpdate(userId, {
    $set: { refreshTokens: [] }
  });
};
