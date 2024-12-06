import { RequestHandler } from 'express';
import Joi from '@hapi/joi';
import { User } from '../../models/User';
import { requestHandler } from '../../middleware/request-middleware';
import bcrypt from 'bcrypt';
import { generateJWTandSetCookie } from '../../utils/generateJWTandSetCookie';
import { gen } from 'n-digit-token';
import { sendVerificationEmail } from '../../utils/emailService';
import { EmailError } from '../../errors';

export const addUserSchema = Joi.object().keys({
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required(),
  firstName: Joi.string().required(),
  lastName: Joi.string().required()
}).strict().unknown(false);

const registerWrapper: RequestHandler = async (req, res) => {
  const { email, password, firstName, lastName } = req.body;

  try {
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'Email already registered, Go to login page!'
      });
    }

  // Generate secure 6-digit verification token
  const verificationToken = gen(6);
  const hashedVerificationToken = await bcrypt.hash(verificationToken, 10);
  const verificationTokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

  if (email === "ramy.mostfaa@gmail.com") {
    await sendVerificationEmail(email, verificationToken);
  }
  
  // Create new user
  const user = new User({
    email,
    password,
    firstName,
    lastName,
    verificationToken: hashedVerificationToken,
    verificationTokenExpires,
    isVerified: false,
    lastLogin: new Date(),
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
      verificationToken
    });
  } catch (error) {
    if (error instanceof EmailError) {
      return res.status(error.status).json({
        success: false,
        message: error.message
      });
    }
    throw error; // Let the global error handler handle other errors
  }
};

export const register = requestHandler(registerWrapper, { 
  validation: { body: addUserSchema }, 
  skipJwtAuth: true 
});
