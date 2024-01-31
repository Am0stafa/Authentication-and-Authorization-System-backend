const User = require("../model/User");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const validator = require("validator");
const bcrypt = require("bcrypt");
const sendEmail = require("../config/sendEmail");

const getAllUsers = async (req, res) => {
  const users = await User.find();
  if (!users) return res.status(204).json({ message: "No users found" });
  res.json(users);
};

const deleteUser = async (req, res) => {
  if (!req?.params?.id)
    return res.status(400).json({ message: "User ID required" });
  const user = await User.findOne({ _id: req.params.id }).exec();
  if (!user) {
    return res
      .status(204)
      .json({ message: `User ID ${req.params.id} not found` });
  }
  const result = await user.deleteOne({ _id: req.params.id });
  res.json(result);
};

const getUser = async (req, res) => {
  if (!req?.params?.id)
    return res.status(400).json({ message: "User ID required" });
  const user = await User.findOne({ _id: req.params.id }).exec();
  if (!user) {
    return res
      .status(204)
      .json({ message: `User ID ${req.params.id} not found` });
  }
  res.json(user);
};

const isValidEmail = async (req, res) => {
  if (!req?.params?.email)
    return res.status(400).json({ message: "no email address provided" });
  const user = await User.findOne({ email: req.params.email }).exec();
  if (!user) {
    return res.status(200).json({ message: false });
  }
  return res.status(200).json({ message: true });
};

const getMe = async (req, res) => {
  const accessToken = req.headers.authorization.split(" ")[1];

  if (!accessToken) {
    return res.status(401).json({ message: "Access token is required" });
  }

  try {
    const decoded = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
    const userEmail = decoded.UserInfo.email;

    const user = await User.findOne({ email: userEmail }).exec();
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    console.log(user.profilePic);
    res.json(user);
  } catch (error) {
    console.log(error);
    return res.status(403).json({ message: "Invalid or expired access token" });
  }
};

const updateUserDetails = async (req, res) => {
  console.log("updateUserDetails");
  const accessToken = req.headers.authorization.split(" ")[1];

  if (!accessToken) {
    return res.status(401).json({ message: "Access token is required" });
  }

  const { name } = req.body;

  try {
    const decoded = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
    const userEmail = decoded.UserInfo.email;

    const user = await User.findOne({ email: userEmail }).exec();
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    let isUpdated = false;

    // Update name if provided and different from the current one
    if (name && name !== user.name) {
      user.name = name;
      isUpdated = true;
    }

    // Update profile picture if provided
    if (req.file) {
      user.profilePic = req.file.path;
      isUpdated = true;
    }

    // Save changes if either name or profile picture was provided
    if (isUpdated) {
      await user.save();
      res.status(200).json({ message: "User details updated successfully" });
    } else {
      res.status(400).json({ message: "No update information provided" });
    }
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return res.status(403).json({ message: "Access token expired" });
    } else if (error.name === "JsonWebTokenError") {
      return res.status(403).json({ message: "Invalid access token" });
    }
    res.status(500).json({ message: error.message });
  }
};

const sendPasswordResetEmail = async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) {
    return res.status(200).json({ message: "Password reset email sent." });
  }

  const passwordResetToken = crypto.randomBytes(32).toString("hex");
  const hash = crypto
    .createHash("sha256")
    .update(passwordResetToken)
    .digest("hex");
  user.passwordResetToken = hash;
  user.passwordResetExpires = Date.now() + 15 * 60 * 1000; // 15 minutes
  await user.save();

  const link = `http://localhost:3000/reset-password?token=${passwordResetToken}&id=${user._id}`;

  try {
    await sendEmail(
      user.email,
      "Password Reset",
      `Please click on the following link to reset your password: ${link}`
    );
    res.status(200).json({ message: "Password reset email sent." });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Error sending email" });
  }
};

const resetPassword = async (req, res) => {
  const { token, newPassword } = req.body;
  const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
  });

  if (!user) {
    return res.status(400).json({ message: "Token is invalid or has expired" });
  }

  const salt = process.env.SALT;
  const peppers = ["00", "01", "10", "11"];
  const pepper = peppers[Math.floor(Math.random() * 4)];
  const hashPwd = crypto
    .createHash("sha512")
    .update(salt + newPassword + pepper)
    .digest("hex");
  user.password = hashPwd;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save();
  console.log("Password has been reset successfully");

  res.status(200).json({ message: "Password has been reset successfully" });
};

const changeUserRole = async (req, res) => {
  const { email, roleCode } = req.body;
  const accessToken = req.headers.authorization.split(" ")[1];

  if (!accessToken) {
    return res.status(401).json({ message: "Access token is required" });
  }

  try {
    const decoded = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
    const requesterEmail = decoded.UserInfo.email;
    const requester = await User.findOne({ email: requesterEmail }).exec();

    if (!requester || !requester.roles.includes("Admin")) {
      return res
        .status(403)
        .json({ message: "Only admins can change user roles" });
    }
  } catch (error) {
    console.log(error);
    return res.status(403).json({ message: "Invalid or expired access token" });
  }


  if (!email || roleCode === undefined) {
    return res
      .status(400)
      .json({ message: "Email and role code are required" });
  }

  try {
    const user = await User.findOne({ email }).exec();
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Check if the role code is valid
    const roles = require("../config/rolesList");
    const roleEntry = Object.entries(roles).find(
      ([roleName, code]) => code === roleCode
    );
    if (!roleEntry) {
      return res.status(400).json({ message: "Invalid role code" });
    }

    // Update the user's role
    const [newRole, _] = roleEntry;
    user.roles[newRole] = roleCode;
    await user.save();

    res.status(200).json({ message: `User role updated to ${newRole}` });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

module.exports = {
  isValidEmail,
  getAllUsers,
  deleteUser,
  getUser,
  getMe,
  changeUserRole,
  updateUserDetails,
  sendPasswordResetEmail,
  resetPassword,
};
