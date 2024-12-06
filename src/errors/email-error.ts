import { ApplicationError } from './application-error';

export class EmailError extends ApplicationError {
  constructor(message?: string) {
    super(message || 'Email sending failed', 500);
  }
}