const crypto = require("crypto");
const userModel = require("./../model/User");
const validator = require("validator");
const multer = require("multer");
const path = require('path');

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/"); // Make sure this uploads directory exists
  },
  filename: function (req, file, cb) {
    cb(
      null,
      file.fieldname + "-" + Date.now() + path.extname(file.originalname)
    );
  },
});
const upload = multer({ storage: storage });

// register new user
const handelNewUser = async (req, res) => {
  const { email, pwd } = req.body;

  if (!email || !pwd)
    return res
      .status(404)
      .json({ status: "failed", message: "email and password are required" });

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

  if (pwd.length < 8 || pwd.length > 24) {
    return res.status(400).json({
      status: "failed",
      message: "Password must be between 8 and 24 characters",
    });
  }

  const PWD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%]).{8,24}$/;
  if (!PWD_REGEX.test(pwd))
    return res.status(404).json({
      status: "failed",
      message:
        "Must include uppercase and lowercase letters, a number and a special character",
    });

  try {
    const duplicate = await userModel.findOne({ email }).exec();
    if (duplicate)
      return res.status(409).json({
        status: "Conflict",
        message: "A user with this email already exists",
      });

    let name = email.split("@")[0];
    //! validate name from xss
    const nameRegex = /^[a-zA-Z0-9_]{3,25}$/;
    if (!nameRegex.test(name)) name = "user";

    const salt = process.env.SALT;
    const peppers = ["00", "01", "10", "11"];
    const pepper = peppers[Math.floor(Math.random() * 4)];
    const hashPwd = crypto
      .createHash("sha512")
      .update(salt + pwd + pepper)
      .digest("hex");

    if (req.file) {
      const profilePicUrl = req.file.path; 

      await userModel.create({
        name,
        email,
        password: hashPwd,
        profilePic: profilePicUrl, // Save the URL here
      });
    } else {
      await userModel.create({
        name,
        email,
        password: hashPwd,
      });
    }

    res.status(201).json({ success: `New user ${name} created!` });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ status: "failed", message: error.message });
  }
};

module.exports = { handelNewUser, upload };
