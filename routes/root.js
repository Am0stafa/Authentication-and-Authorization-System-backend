const express = require('express');
const router = express.Router();
const path = require('path');

//? must begin with a slash and end with a slash or /index.html and the html is optional REGEX
router.get('^/$|/index(.html)?', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'views', 'index.html'));
}); 


module.exports = router;