const express = require('express');
const router = express.Router();

//------------ Importing Controllers ------------//
const AuthController = require('../controllers/authController')
//------------ Importing Middlewares ------------//
const UserValidation = require('../middlewares/UserValidation')

router.post('/register', UserValidation, AuthController.register);
router.post('/login', AuthController.login);
router.get('/verify/:token', AuthController.verify);
router.post('/resend', AuthController.resend);
router.post('/forgot', AuthController.forgotPassword);

module.exports = router;