import {
  PASSWORD_RESET_REQUEST_TEMPLATE,
  PASSWORD_RESET_SUCCESS_TEMPLATE,
  VERIFICATION_EMAIL_TEMPLATE,
} from "./emailTemplates";
import { mailtrapClient, sender } from "./mailtrap.config";
import { EmailError } from "../errors";

export const sendVerificationEmail = async (email: string, verificationToken: string): Promise<void> => {
  const recipients = [{ email }];

  try {
    const response = await mailtrapClient.send({
      from: sender,
      to: recipients,
      subject: "Verify your email",
      html: VERIFICATION_EMAIL_TEMPLATE.replace("{verificationCode}", verificationToken),
      category: "Email Verification",
    });

    if (!response.success) {
      throw new Error('Email sending failed');
    }
  } catch (error) {
    console.error('Verification email sending failed:', error?.response?.data || error);
    throw new EmailError(
      `Failed to send verification email. ${error?.response?.data?.message || error.message}`
    );
  }
};

export const sendPasswordResetEmail = async (email: string, resetURL: string): Promise<void> => {
  const recipients = [{ email }];

  try {
    await mailtrapClient.send({
      from: sender,
      to: recipients,
      subject: "Reset your password",
      html: PASSWORD_RESET_REQUEST_TEMPLATE.replace("{resetURL}", resetURL),
      category: "Password Reset",
    });
  } catch (error) {
    console.error('Password reset email sending failed:', error);
    throw new EmailError(`Failed to send password reset email to ${email}`);
  }
};

export const sendResetSuccessEmail = async (email: string): Promise<void> => {
  const recipients = [{ email }];

  try {
    await mailtrapClient.send({
      from: sender,
      to: recipients,
      subject: "Password Reset Successful",
      html: PASSWORD_RESET_SUCCESS_TEMPLATE,
      category: "Password Reset",
    });
  } catch (error) {
    console.error('Password reset success email sending failed:', error);
    throw new EmailError(`Failed to send password reset success email to ${email}`);
  }
}; 