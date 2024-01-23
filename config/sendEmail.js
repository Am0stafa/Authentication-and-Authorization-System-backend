const nodemailer = require('nodemailer');

const sendEmail = async (to, subject, text) => {
  let transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USERNAME, // Your email username
      pass: process.env.EMAIL_PASSWORD, // Your email password
    },
  });

  let mailOptions = {
    from: process.env.EMAIL_USERNAME,
    to: to,
    subject: subject,
    text: text,
  };

  await transporter.sendMail(mailOptions);
};

module.exports = sendEmail;