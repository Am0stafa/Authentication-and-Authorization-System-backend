import { RequestHandler } from 'express';
import Joi from '@hapi/joi';
import { User } from '../../models/User';
import { requestHandler } from '../../middleware/request-middleware';
import crypto from 'crypto';
import bcrypt from 'bcrypt';

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
      message: 'Email already registered'
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

  await user.save();

  // Remove password from response
  const userResponse = user.toObject();
  delete userResponse.password;

  return res.status(201).json({
    success: true,
    message: 'User registered successfully',
    data: userResponse,
    verificationLink // In a real-world scenario, this would be sent via email
  });
};

export const register = requestHandler(registerWrapper, { 
  validation: { body: addUserSchema }, 
  skipJwtAuth: true 
});
