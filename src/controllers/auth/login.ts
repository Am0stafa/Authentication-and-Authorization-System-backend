import { RequestHandler } from 'express';
import Joi from '@hapi/joi';
import { User } from '../../models/User';
import { requestHandler } from '../../middleware/request-middleware';
import { BadRequest } from '../../errors';
import { generateJWTandSetCookie } from '../../utils/generateJWTandSetCookie';

export const loginSchema = Joi.object().keys({
  email: Joi.string().email().required(),
  password: Joi.string().required()
}).strict();

const loginWrapper: RequestHandler = async (req, res) => {
  const { email, password } = req.body;

  // Find user and explicitly select password field
  const user = await User.findOne({ email }).select('+password +isVerified');
  
  if (!user) {
    throw new BadRequest('Invalid email or password');
  }

  // Check if email is verified
  if (!user.isVerified) {
    return res.status(403).json({
      success: false,
      message: 'Please verify your email before logging in'
    });
  }

  // Verify password
  const isValidPassword = await user.comparePassword(password);
  if (!isValidPassword) {
    throw new BadRequest('Invalid email or password');
  }

  // Update last login
  await User.findByIdAndUpdate(user._id, {
    lastLogin: new Date()
  });

  // Generate JWT and set cookie
  generateJWTandSetCookie(res, { userId: user._id.toString() });

  // Get user data without sensitive fields
  const userResponse = await User.findById(user._id).lean();

  return res.status(200).json({
    success: true,
    message: 'Login successful',
    data: userResponse
  });
};

export const login = requestHandler(loginWrapper, {
  validation: { body: loginSchema },
  skipJwtAuth: true
});
