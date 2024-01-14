const User = require("../model/User");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const validator = require("validator");
const useragent = require("express-useragent");
const axios = require("axios");
          

// login
const handleLogin = async (req, res) => {
  const { email, pwd } = req.body;
  if (!email || !pwd)
    return res
      .status(400)
      .json({ message: "Email and password are required." });

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

  if (!match) return res.sendStatus(401); //Unauthorized

  const roles = Object.values(foundUser.roles).filter(Boolean);

  const accessToken = jwt.sign(
    {
      UserInfo: {
        email: foundUser.email,
        roles: roles,
      },
    },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: "15m" }
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

module.exports = { handleLogin };
