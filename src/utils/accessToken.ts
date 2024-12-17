import jwt from 'jsonwebtoken';

interface AccessTokenPayload {
  userId: string;
  type: 'access';
}

export const generateAccessToken = (userId: string): string => {
  if (!process.env.JWT_ACCESS_SECRET) {
    throw new Error('JWT_ACCESS_SECRET is not defined');
  }

  const payload: AccessTokenPayload = {
    userId,
    type: 'access'
  };

  return jwt.sign(payload, process.env.JWT_ACCESS_SECRET, {
    expiresIn: '15m', // Short lived
    algorithm: 'ES512'
  });
};

export const verifyAccessToken = (token: string): AccessTokenPayload => {
  if (!process.env.JWT_ACCESS_SECRET) {
    throw new Error('JWT_ACCESS_SECRET is not defined');
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET) as AccessTokenPayload;
    if (decoded.type !== 'access') {
      throw new Error('Invalid token type');
    }
    return decoded;
  } catch (error) {
    throw new Error('Invalid access token');
  }
};
