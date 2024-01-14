const express = require('express');
const router = express.Router();
const { handelNewUser } = require('../controllers/registerController');
const { upload } = require('../controllers/registerController'); // Assuming you export it from there

router.post('/', upload.single('profileImg'), handelNewUser);

module.exports = router;