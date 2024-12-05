import { RequestHandler } from 'express';
import Joi from '@hapi/joi';
import { User } from '../../models/User';
import { requestHandler } from '../../middleware/request-middleware';
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import { generateJWTandSetCookie } from '../../utils/generateJWTandSetCookie';

export const addUserSchema = Joi.object().keys({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  firstName: Joi.string().required(),
  lastName: Joi.string().required()
});

const registerWrapper: RequestHandler = async (req, res) => {
  const { email, password, firstName, lastName } = req.body;

  // Check if user already exists
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.status(400).json({
      success: false,
      message: 'Email already registered, Go to login page!'
    });
  }

  // Generate verification token
  const verificationToken = crypto.randomBytes(32).toString('hex');
  const hashedVerificationToken = await bcrypt.hash(verificationToken, 10);
  const verificationTokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

  // Create verification link
  const verificationLink = `${req.protocol}://${req.get('host')}/verify/${verificationToken}`;

  // Create new user
  const user = new User({
    email,
    password,
    firstName,
    lastName,
    verificationToken: hashedVerificationToken,
    verificationTokenExpires,
    isVerified: false
  });

  // Save user and immediately retrieve without password
  await user.save();

  // Authenticate user by generating JWT and setting cookie
  generateJWTandSetCookie(res, { userId: user._id.toString() });

  // Retrieve user without password or other sensitive fields
  const userResponse = await User.findById(user._id).lean();

  return res.status(201).json({
    success: true,
    message: 'User registered successfully',
    data: userResponse,
    verificationLink
  });
};

export const register = requestHandler(registerWrapper, { 
  validation: { body: addUserSchema }, 
  skipJwtAuth: true 
});
