import { Router } from 'express';
import swaggerUi from 'swagger-ui-express';
import apiSpec from '../swagger-doc.json';

import * as AuthController from './controllers/auth';

export const router = Router();

// Auth routes
router.post('/auth/register', AuthController.register);
router.post('/auth/login', AuthController.login);

if (process.env.NODE_ENV === 'development') {
  router.use('/dev/api-docs', swaggerUi.serve);
  router.get('/dev/api-docs', swaggerUi.setup(apiSpec));
}
