const User = require("../model/User");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const validator = require("validator");

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

// {
//   "email": "abdo@gmail.com",
//   "newRole": "Admin"
// }
const changeUserRole = async (req, res) => {
  const { email, newRole } = req.body;
  if (!userId || !newRole) {
    return res
      .status(400)
      .json({ message: "User ID and new role are required" });
  }

  try {
    const user = await User.findOne({ email }).exec();
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Assuming newRole is the key from the roles object (e.g., "Admin", "Editor", "User")
    const roles = require("../config/rolesList");
    if (roles[newRole] === undefined) {
      return res.status(400).json({ message: "Invalid role" });
    }

    // Update the user's role
    user.roles[newRole] = roles[newRole];
    await user.save();

    res.status(200).json({ message: `User role updated to ${newRole}` });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

const updateUserDetails = async (req, res) => {
  const accessToken = req.headers.authorization.split(" ")[1];

  if (!accessToken) {
    return res.status(401).json({ message: "Access token is required" });
  }

  const { name, pwd } = req.body;

  try {
    const decoded = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
    const userEmail = decoded.UserInfo.email;

    const user = await User.findOne({ email: userEmail }).exec();
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }


    // Update name
    if (name && name !== user.name) {
      user.name = name;
    }

    // Update password
    if (pwd) {
      const salt = process.env.SALT;
      const peppers = ["00", "01", "10", "11"];
      const currentHashedPwd = peppers.find((pep) => {
        return (
          crypto
            .createHash("sha512")
            .update(salt + pwd + pep)
            .digest("hex") === user.password
        );
      });

      if (currentHashedPwd) {
        return res
          .status(400)
          .json({
            message: "New password must be different from the old password",
          });
      }

      const newPepper = peppers[Math.floor(Math.random() * peppers.length)];
      const newHashedPwd = crypto
        .createHash("sha512")
        .update(salt + pwd + newPepper)
        .digest("hex");

      user.password = newHashedPwd;
    }

    // Update profile picture if provided
    if (req.file) {
      user.profilePic = req.file.path;
    }

    await user.save();
    res.status(200).json({ message: "User details updated successfully" });
  } catch (error) {
    if (error.name === "TokenExpiredError") {
      return res.status(403).json({ message: "Access token expired" });
    } else if (error.name === "JsonWebTokenError") {
      return res.status(403).json({ message: "Invalid access token" });
    }
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
};
