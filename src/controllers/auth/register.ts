import { RequestHandler } from 'express';
import Joi from '@hapi/joi';
import { User } from '../../models/User';
import { requestHandler } from '../../middleware/request-middleware';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import { gen } from 'n-digit-token';
import { sendVerificationEmail } from '../../utils/emailService';
import { EmailError } from '../../errors';
import { getClientInfo } from '../../utils/clientInfo';
import { generateAccessToken } from '../../utils/accessToken';
import { generateRefreshToken } from '../../utils/refreshToken';

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

    // Save user
    await user.save();

    // Generate tokens
    const clientInfo = getClientInfo(req);
    const accessToken = generateAccessToken(user._id.toString());
    const { token: refreshToken, expiresAt } = await generateRefreshToken(
      user._id.toString(),
      {
        userAgent: JSON.stringify(clientInfo.userAgent),
        ipAddress: clientInfo.ipAddress,
        family: crypto.randomBytes(32).toString('hex'),
        version: 1
      }
    );

    // Set refresh token cookie
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      sameSite: 'lax',
      expires: expiresAt,
      path: '/'
    });

    // Retrieve user without password
    const userResponse = await User.findById(user._id).lean();

    return res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: {
        ...userResponse,
        accessToken,
        verificationToken
      }
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
