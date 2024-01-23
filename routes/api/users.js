const express = require("express");
const router = express.Router();
const usersController = require("../../controllers/usersController");
const ROLES_LIST = require("../../config/rolesList");
const verifyRoles = require("../../middleware/verifyRoles");
const { verifyJWT } = require("../../middleware/verifyJWT");
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });

router.route("/getMail/:email").get(usersController.isValidEmail);

router.post('/forgot-password', usersController.sendPasswordResetEmail);
router.post('/reset-password', usersController.resetPassword);

router.use(verifyJWT);

router.route("/me").get(usersController.getMe);

router.patch("/update", upload.single("profilePic"), usersController.updateUserDetails);

router
  .route("/")
  .get(verifyRoles(ROLES_LIST.Admin), usersController.getAllUsers);

router
  .route("/changeRole")
  .post(verifyRoles(ROLES_LIST.Admin), usersController.changeUserRole);

router
  .route("/:id")
  .get(verifyRoles(ROLES_LIST.Admin), usersController.getUser)
  .delete(verifyRoles(ROLES_LIST.Admin), usersController.deleteUser);

module.exports = router;
