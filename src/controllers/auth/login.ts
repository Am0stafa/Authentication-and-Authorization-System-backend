import { RequestHandler } from 'express';
import jwt from 'jsonwebtoken';
import { requestHandler } from '../../middleware/request-middleware';

const loginWrapper: RequestHandler = async (req, res) => {
  return res.status(200).json({
    message: 'Hi its login'
  });
};

export const login = requestHandler(loginWrapper, { skipJwtAuth: true });
