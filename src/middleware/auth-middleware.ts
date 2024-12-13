/* eslint-disable @typescript-eslint/explicit-module-boundary-types */
import { Request, Response, NextFunction } from 'express';
import axios from 'axios';

interface AuthOptions {
  authServiceUrl: string;
  onError?: (error: any) => void;
}

interface VerifyTokenResponse {
  success: boolean;
  data: {
    userId: string;
    email: string;
    firstName: string;
    lastName: string;
  };
}

export const createAuthMiddleware = (options: AuthOptions) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    const token = req.cookies.token || req.headers.authorization?.replace('Bearer ', '');

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'No authentication token provided'
      });
    }

    try {
      const response = await axios.post<VerifyTokenResponse>(
        `${options.authServiceUrl}/auth/verify-token`,
        {},
        {
          headers: { Authorization: `Bearer ${token}` }
        }
      );

      // Attach user data to request with proper typing
      req.user = response.data.data;
      next();
    } catch (error) {
      if (options.onError) {
        options.onError(error);
      }
      return res.status(401).json({
        success: false,
        message: 'Invalid or expired token'
      });
    }
  };
}; 