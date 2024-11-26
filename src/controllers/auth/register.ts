import { RequestHandler } from 'express';
import Joi from '@hapi/joi';
import { requestHandler } from '../../middleware/request-middleware';

export const addUserSchema = Joi.object().keys({
  email: Joi.string().required(),
  password: Joi.string().required(),
  firstName: Joi.string().required(),
  lastName: Joi.string().required()
});

const registerWrapper: RequestHandler = async (req, res) => {
  return res.status(200).json({
    message: 'Hi its register'
  });
};

export const register = requestHandler(registerWrapper, { validation: { body: addUserSchema }, skipJwtAuth: true });
