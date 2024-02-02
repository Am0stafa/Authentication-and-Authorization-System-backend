const User = require("../model/User");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const validator = require("validator");
const useragent = require("express-useragent");
const axios = require("axios");
const FailedLoginAttempt = require("../model/FailedLoginAttempt");
const redis = require('../config/redisConnect');
const sendEmail = require("../config/sendEmail");
const {OAuth2Client} = require('google-auth-library');

// login
const handleLogin = async (req, res) => {
  // get the fingerprint for the current visitor
  const userFingerprint = req.fingerprint;
  console.log("Fingerprint:", userFingerprint.hash);

  const { email, pwd, code } = req.body;
  if (!email || !pwd || !code)
    return res
      .status(400)
      .json({ message: "Email, password, and 2FA code are required." });


  if (email.length > 256) {
    return res
      .status(400)
      .json({ status: "failed", message: "Email is too long" });
  }

  if (!validator.isEmail(email)) {
    return res
      .status(404)
      .json({ status: "failed", message: "Email is not valid" });
  }

  const foundUser = await User.findOne({ email }).exec();
  if (!foundUser) return res.sendStatus(401); //Unauthorized

  // Check for failed login attempts
  let failedLoginRecord = await FailedLoginAttempt.findOne({
    userId: foundUser._id,
  });
  // this user is blocked
  if (
    failedLoginRecord &&
    failedLoginRecord.lockUntil &&
    failedLoginRecord.lockUntil > Date.now()
  ) {
    return res.status(429).json({
      message: "Too many failed login attempts. Please try again later.",
    });
  }

  const foundPass = foundUser.password;
  const salt = process.env.SALT;
  const peppers = ["00", "01", "10", "11"];

  const match = peppers.find((pep) => {
    return (
      crypto
        .createHash("sha512")
        .update(salt + pwd + pep)
        .digest("hex") === foundPass
    );
  });

  if (!match) {
    // Increment failed attempts
    if (!failedLoginRecord) {
      failedLoginRecord = new FailedLoginAttempt({ userId: foundUser._id });
    }
    failedLoginRecord.attempts += 1;
    if (failedLoginRecord.attempts >= 5) {
      failedLoginRecord.lockUntil = new Date(Date.now() + 10 * 60 * 1000); // Lock for 10 minutes
      failedLoginRecord.attempts = 0; // Reset attempts
    }
    await failedLoginRecord.save();
    return res.sendStatus(401); //Unauthorized
  }
  // Check if 2FA code is valid
  const is2FACodeValid = crypto.createHash("sha256").update(code).digest("hex") === foundUser.emailVerificationToken;
  if (!is2FACodeValid) {
    return res.status(401).json({ message: "Invalid 2FA code." });
  }
  foundUser.emailVerificationToken = null;
  await foundUser.save();

  const roles = Object.values(foundUser.roles).filter(Boolean);

  const accessToken = jwt.sign(
    {
      UserInfo: {
        email: foundUser.email,
        roles: roles,
      },
    },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: "10m" }
  );

  const newRefreshToken = jwt.sign(
    { email: foundUser.email },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: "60d" }
  );

  //* in case of cookie found

  //! there could be an existing cookie if we didn't sign out but the user went back to the login page if found we do 2 things
  const cookies = req.cookies;

  let newRefreshTokenArray = !cookies?.jwt
    ? foundUser.refreshToken
    : foundUser.refreshToken.filter((rt) => rt !== cookies.jwt);

  if (cookies?.jwt) {
    /* 
      Scenario added here: 
          1) User logs in but never uses RT and does not logout 
          2) RT is stolen and used by the hacker
          3) If 1 & 2, reuse detection is needed to clear all RTs when user logs in
    */
    const refreshToken = cookies.jwt;
    const foundToken = await User.findOne({ refreshToken }).exec();

    //! if we dont find the token we know that its already had been used then because our user would not have used that token to it should be in the array even if it is expired. However, if they have not used there token but it isn't in there then we know somebody else had used it
    if (!foundToken) {
      console.log("attempted refresh token reuse at login!");
      newRefreshTokenArray = [];
    }
    res.clearCookie("jwt", { httpOnly: true, sameSite: "None", secure: true });
  }
  // const userInfo = await getUserInfo(req);
  foundUser.refreshToken = [...newRefreshTokenArray, newRefreshToken];
  // foundUser.loginInfo.push(userInfo);
  const user = await foundUser.save();

  // Creates Secure Cookie with refresh token
  res.cookie("jwt", newRefreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "None",
    maxAge: 60 * 60 * 24 * 60, // 60 days
  });
  await redis.set(`refreshToken:${foundUser._id}`, newRefreshToken, 'EX', 60 * 60 * 24 * 60);
  
  if (failedLoginRecord) {
    failedLoginRecord.attempts = 0;
    failedLoginRecord.lockUntil = null;
    await failedLoginRecord.save();
  }
  // Send authorization roles and access token to user
  res.json({ user: foundUser.email, roles, accessToken, name: foundUser.name });
};

const getUserInfo = async (req) => {
  // const APIKEY = process.env.APIKEY;
  // const ua = useragent.parse(req.headers["user-agent"]);
  // const device = ua.isMobile ? "Mobile" : ua.isTablet ? "Tablet" : "Desktop";
  // const browser = ua.browser;
  // // api call to http://api.ipstack.com/41.130.142.138?access_key=d00cbad7e4f89ff2a9ad32154d75207b&format=1
  // let ipAdd = req.ip;
  // if (ipAdd.substr(0, 7) === "::ffff:") {
  //   ipAdd = ipAdd.substr(7);
  // }
  // const url = `http://api.ipstack.com/${ipAdd}?access_key=${APIKEY}&format=1`;
  // const data = await axios.get(url).then((res) => res.data);
  // console.log(data);
  // const ip = data.ip;
  // const location = `${data.city}, ${data.region_name}`;

  return {
    device,
    browser,
    ip,
    location,
  };
};

const getUserData = async (access_token) => {

  const response = await fetch(`https://www.googleapis.com/oauth2/v3/userinfo?access_token=${access_token}`);
  
  //console.log('response',response);
  const data = await response.json();
  console.log('data',data);
}

const send2fa = async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ message: "Email is required" });
  }

  try {
    const user = await User.findOne({ email }).exec();
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Generate a secure 6 digit code
    const code = crypto.randomInt(100000, 999999);
    console.log("2FA code:", code); 
    const hash = crypto.createHash("sha256").update(code.toString()).digest("hex");

    user.emailVerificationToken = hash;
    await user.save();

    // Send email with the 2FA code
    const subject = "Your 2FA Code";
    const text = `Your 2FA code is: ${code}`;
    await sendEmail(email, subject, text);

    res.status(200).json({ message: "2FA code sent to email" });
  } catch (error) {
    console.error("Error sending 2FA code:", error);
    res.status(500).json({ message: "An error occurred while sending the 2FA code" });
  }
};

// Generate a URL for the consent dialog
const loginWithGoogle = async (req, res) => {
  res.header("Access-Control-Allow-Origin", 'http://localhost:3000');
  res.header("Access-Control-Allow-Credentials", 'true');
  res.header("Referrer-Policy","no-referrer-when-downgrade");
  const redirectURL = 'http://127.0.0.1:3000/oauth';

  const oAuth2Client = new OAuth2Client(
    process.env.CLIENT_ID,
    process.env.CLIENT_SECRET,
      redirectURL
    );

    // Generate the url that will be used for the consent dialog.
    const authorizeUrl = oAuth2Client.generateAuthUrl({
      access_type: 'offline',
      scope: 'https://www.googleapis.com/auth/userinfo.profile  openid ',
      prompt: 'consent'
    });

    return res.status(200).json({ url: authorizeUrl });
}

const oauthGoogle = async (req, res) => {
  const code = req.query.code;
  const redirectURL = 'http://127.0.0.1:3000/oauth';
  try{
    const oAuth2Client = new OAuth2Client(
      process.env.CLIENT_ID,
      process.env.CLIENT_SECRET,
      redirectURL
    );
    const r =  await oAuth2Client.getToken(code);
    await oAuth2Client.setCredentials(r.tokens);
    console.info('Tokens acquired.');
    const user = oAuth2Client.credentials;
    console.log('credentials',user);
    await getUserData(oAuth2Client.credentials.access_token);
    } catch (err) {
      console.log('Error logging in with OAuth2 user', err);
    }


    return res.redirect(303, 'http://localhost:5173/');
  
}

module.exports = {handleLogin, send2fa, loginWithGoogle};
