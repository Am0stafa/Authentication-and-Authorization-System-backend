const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');

router.post('/', authController.handleLogin);
// send 2fa
router.post('/send2fa', authController.send2fa);


module.exports = router;