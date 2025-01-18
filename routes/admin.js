const express = require('express');
const router = express.Router();
const { signup } = require('../src/controllers/superAdminController');

// Signup route
router.post('/signup', signup);

module.exports = router;
