import { RequestHandler } from 'express';
import jwt from 'jsonwebtoken';
import { requestHandler } from '../../middleware/request-middleware';
import { User } from '../../models/User';
import { UnauthorizedRequest } from '../../errors';

const verifyTokenWrapper: RequestHandler = async (req, res) => {
  const token = req.cookies.token || req.headers.authorization?.replace('Bearer ', '');

  if (!token) {
    throw new UnauthorizedRequest('No token provided');
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET) as { userId: string };
    
    // Check if user still exists and is verified
    const user = await User.findById(decoded.userId).select('+isVerified');
    if (!user || !user.isVerified) {
      throw new UnauthorizedRequest('Invalid token');
    }

    return res.status(200).json({
      success: true,
      data: {
        userId: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName
      }
    });
  } catch (error) {
    throw new UnauthorizedRequest('Invalid token');
  }
};

export const verifyToken = requestHandler(verifyTokenWrapper, {
  skipJwtAuth: true
}); 