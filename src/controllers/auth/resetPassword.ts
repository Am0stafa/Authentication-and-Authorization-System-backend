import { RequestHandler } from 'express';
import Joi from '@hapi/joi';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { User } from '../../models/User';
import { requestHandler } from '../../middleware/request-middleware';
import { BadRequest } from '../../errors';
import { sendResetSuccessEmail } from '../../utils/emailService';

export const resetPasswordSchema = Joi.object().keys({
  token: Joi.string().required(),
  password: Joi.string().min(6).required()
}).strict();

const resetPasswordWrapper: RequestHandler = async (req, res) => {
  const { token, password } = req.body;

  let decoded;
  try {
    decoded = jwt.verify(token, process.env.JWT_SECRET) as { userId: string };
  } catch (error) {
    throw new BadRequest('Invalid or expired reset token');
  }

  // Find user with valid reset token
  const user = await User.findOne({
    _id: decoded.userId,
    resetPasswordToken: { $exists: true },
    resetPasswordExpires: { $gt: new Date() }
  }).select('+resetPasswordToken +password');

  if (!user) {
    throw new BadRequest('Invalid or expired reset token');
  }

  // Verify token hasn't been used
  const isValidToken = await bcrypt.compare(token, user.resetPasswordToken);
  if (!isValidToken) {
    throw new BadRequest('Invalid reset token');
  }

  // Ensure new password is different
  const isSamePassword = await bcrypt.compare(password, user.password);
  if (isSamePassword) {
    throw new BadRequest('New password must be different from current password');
  }

  // Update password and clear reset token
  user.password = password;
  user.resetPasswordToken = undefined;
  user.resetPasswordExpires = undefined;
  await user.save();

  // Send success email
  await sendResetSuccessEmail(user.email);

  return res.status(200).json({
    success: true,
    message: 'Password reset successful'
  });
};

export const resetPassword = requestHandler(resetPasswordWrapper, {
  validation: { body: resetPasswordSchema },
  skipJwtAuth: true
}); 