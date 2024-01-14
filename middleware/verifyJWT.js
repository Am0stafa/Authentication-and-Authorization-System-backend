const jwt = require("jsonwebtoken");

const verifyJWT = (req, res, next) => {
  //! here we verify the access token
  //! the frontend might have authorization in uppercase

  const authHeader = req.headers.authorization || req.headers.Authorization;
  if (!authHeader?.startsWith("Bearer "))
    return res.status(401).json({ message: "no token found" });

  const token = authHeader.split(" ")[1]; // bearer token
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) return res.sendStatus(403); //invalid token
    req.user = decoded.UserInfo.email;
    req.roles = decoded.UserInfo.roles;
    next();
  });
};

module.exports = { verifyJWT };

