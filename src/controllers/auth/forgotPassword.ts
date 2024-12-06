import { RequestHandler } from 'express';
import jwt from 'jsonwebtoken';
import Joi from '@hapi/joi';
import bcrypt from 'bcrypt';
import { User } from '../../models/User';
import { requestHandler } from '../../middleware/request-middleware';
import { sendPasswordResetEmail } from '../../utils/emailService';

export const forgotPasswordSchema = Joi.object().keys({
  email: Joi.string().email().required()
}).strict();

const forgotPasswordWrapper: RequestHandler = async (req, res) => {
  const { email } = req.body;

  // Start async operations in parallel for consistent timing
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [user, _] = await Promise.all([
    User.findOne({ email }),
    // Always perform a hash operation regardless of user existence
    bcrypt.hash(email + Date.now(), 10)
  ]);


  if (user) {
    // Generate reset token (JWT)
    const resetToken = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Hash token before saving
    const hashedToken = await bcrypt.hash(resetToken, 10);

    // Save hashed token and expiry
    await User.findByIdAndUpdate(user._id, {
      resetPasswordToken: hashedToken,
      resetPasswordExpires: new Date(Date.now() + 3600000) // 1 hour
    });

    // Generate reset URL
    const resetURL = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;

    // Send email
    await sendPasswordResetEmail(email, resetURL);
  } else {
    // Simulate the time it would take to send an email
    await new Promise(resolve => setTimeout(resolve, 500));
  }

  // Same response regardless of user existence
  return res.status(200).json({
    success: true,
    message: 'If an account exists with this email, a password reset link will be sent.'
  });
};

export const forgotPassword = requestHandler(forgotPasswordWrapper, {
  validation: { body: forgotPasswordSchema },
  skipJwtAuth: true
}); 