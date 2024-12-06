import { MailtrapClient } from "mailtrap";
import * as dotenv from "dotenv";
import path from 'path';

// Configure dotenv with explicit path
dotenv.config({ path: path.resolve(process.cwd(), '.env') });

if (!process.env.EMAIL_API_KEY) {
  throw new Error('Mailtrap configuration is missing in environment variables');
}

export const mailtrapClient = new MailtrapClient({ token: process.env.EMAIL_API_KEY });

// Using Mailtrap's testing domain as recommended
export const sender = {
  email: "hello@demomailtrap.com",
  name: "Auth Service",
}; 