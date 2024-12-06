import { RequestHandler } from 'express';
import { User } from '../../models/User';
import { requestHandler } from '../../middleware/request-middleware';
import { BadRequest } from '../../errors';
import bcrypt from 'bcrypt';
import Joi from '@hapi/joi';

export const verifyEmailSchema = Joi.object().keys({
  email: Joi.string().email().required(),
  token: Joi.string().length(6).required()
}).strict();

const verifyEmailWrapper: RequestHandler = async (req, res) => {
  const { email, token } = req.body;

  // Find specific user by email with non-expired token
  const user = await User.findOne({ 
    email,
    verificationToken: { $exists: true },
    isVerified: false,
    verificationTokenExpires: { $gt: new Date() }
  }).select('+verificationToken +isVerified +verificationTokenExpires');

  if (user.verificationToken === '1') {
    return res.status(400).json({
      success: false,
      message: 'Try again later'
    });
  }

  if (!user) {
    throw new BadRequest('Invalid or expired verification token');
  }

  // Verify the token
  const isValidToken = await bcrypt.compare(token, user.verificationToken);
  if (!isValidToken) {
    throw new BadRequest('Invalid or expired verification token');
  }

  // Update user verification status
  await User.findByIdAndUpdate(user._id, {
    $set: { isVerified: true },
    $unset: { 
      verificationToken: 1,
      verificationTokenExpires: 1
    }
  }, { new: true });

  return res.status(200).json({
    success: true,
    message: 'Email verified successfully'
  });
};

export const verifyEmail = requestHandler(verifyEmailWrapper, {
  validation: { body: verifyEmailSchema },
  skipJwtAuth: true
}); 