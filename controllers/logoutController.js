const User = require("../model/User");

const handleLogout = async (req, res) => {
  //! On client also delete the accessToken in the memory in the client application

  const cookies = req.cookies;
  if (!cookies?.jwt) return res.sendStatus(204); //No content
  const refreshToken = cookies.jwt;

  const foundUser = await User.findOne({ refreshToken }).exec();

  if (!foundUser) {
    //* we didnt find a user but we have a cookie so just delete it
    res.clearCookie("jwt", { httpOnly: true, sameSite: "None", secure: true });
    return res.sendStatus(204);
  }

  //! we wont set it to an empty array to support multi device login as setting it to an empty array will log all devices out
  foundUser.refreshToken = foundUser.refreshToken.filter(
    (rt) => rt !== refreshToken
  );

  await foundUser.save();

  res.clearCookie("jwt", { httpOnly: true, sameSite: "None" }); //, secure: true
  res.sendStatus(204);
};

module.exports = { handleLogout };
