/*
    req.roles passed from the jwt
    rolesArray the roles that is passed in that will be allowed
    we map through the roles that was assigned to this user and comparing them to get true or false with the roles array that was passed into this route
    @param allowedRoles {integer} we take code
    @return {status} either pass or no
*/
const verifyRoles = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req?.roles) return res.sendStatus(401); // unauthorized
    const rolesArray = [...allowedRoles];
    const result = req.roles
      .map((role) => rolesArray.includes(role))
      .find((val) => val === true); //? we need at least one to be true
    if (!result) return res.sendStatus(401); //! no trues
    next();
  };
};

module.exports = verifyRoles;
