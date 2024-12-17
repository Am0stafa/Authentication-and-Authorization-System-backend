import { RequestHandler } from 'express';
import jwt from 'jsonwebtoken';
import { requestHandler } from '../../middleware/request-middleware';
import { User } from '../../models/User';
import { UnauthorizedRequest } from '../../errors';

interface JWTPayload {
  userId: string;
  type: 'access';
  exp: number;
  iat: number;
}

const verifyTokenWrapper: RequestHandler = async (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');

  if (!token) {
    throw new UnauthorizedRequest('No token provided');
  }

  try {
    // Verify token with correct secret
    const decoded = jwt.verify(
      token, 
      process.env.JWT_ACCESS_SECRET
    ) as JWTPayload;

    // Verify token type
    if (decoded.type !== 'access') {
      throw new UnauthorizedRequest('Invalid token type');
    }

    // Check token expiration explicitly
    if (decoded.exp * 1000 < Date.now()) {
      throw new UnauthorizedRequest('Token has expired');
    }
    
    // Check if user still exists and is verified
    const user = await User.findById(decoded.userId)
      .select('+isVerified +lastLogin')
      .lean();

    if (!user) {
      throw new UnauthorizedRequest('User no longer exists');
    }

    if (!user.isVerified) {
      throw new UnauthorizedRequest('User email is not verified');
    }

    // Check if token was issued before the last login
    if (decoded.iat * 1000 < user.lastLogin.getTime()) {
      throw new UnauthorizedRequest('Token was issued before last login');
    }

    return res.status(200).json({
      success: true,
      data: {
        userId: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        isVerified: user.isVerified
      }
    });
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) {
      throw new UnauthorizedRequest('Invalid token format');
    }
    if (error instanceof jwt.TokenExpiredError) {
      throw new UnauthorizedRequest('Token has expired');
    }
    throw error;
  }
};

export const verifyToken = requestHandler(verifyTokenWrapper, {
  skipJwtAuth: true
}); 