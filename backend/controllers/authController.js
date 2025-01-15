const passport = require('passport');
const bcryptjs = require('bcryptjs');
const nodemailer = require('nodemailer');
const { google } = require("googleapis");
const OAuth2 = google.auth.OAuth2;
const jwt = require('jsonwebtoken');
const JWT_KEY = "jwtactive987";
const JWT_RESET_KEY = "jwtreset987";

const AuthServices = require('../services/AuthServices');

//------------ User Model ------------//
const User = require('../models/User');

//------------ Register ------------//
exports.register = async (req, res) => {
  const respond = await AuthServices.register(req.headers, req.body);
  res.status(200).json(respond);
};

//------------ Login ------------//
exports.login = async (req, res) => {
  const respond = await AuthServices.login(req.body);
  res.status(200).json(respond);
};

//------------ Verify Account ------------//
exports.verify = async (req, res) => {
  console.log("verify", req.params);
  const respond = await AuthServices.verify(req.params);
  res.status(200).json(respond);
};

//------------ Resend Mail ------------//
exports.resend = async (req, res) => {
  const respond = await AuthServices.resend(req.user);
  res.status(200).json(respond);
};

//------------ Forgot Password ------------//
exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ success: false, message: 'User with this email not found.' });
    }

    // Generate a reset token and expiration time
    const resetToken = user.generateResetToken();
    await user.save();

    // Send reset token to the user's email
    const transporter = nodemailer.createTransport({
      service: 'gmail', // You can use other services
      auth: {
        user: 'your-email@gmail.com', // Replace with your email
        pass: 'your-email-password',  // Replace with your email password or app password
      },
    });

    const mailOptions = {
      from: 'your-email@gmail.com',
      to: email,
      subject: 'Password Reset Request',
      text: `Here is your password reset token: ${resetToken}\nIt will expire in 1 hour.`,
    };

    await transporter.sendMail(mailOptions);

    return res.status(200).json({ success: true, message: 'Password reset token sent to your email.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Error sending reset email.' });
  }
};

//------------ Redirect to Reset ------------//
exports.gotoReset = (req, res) => {
  const { token } = req.params;

  if (token) {
    jwt.verify(token, JWT_RESET_KEY, (err, decodedToken) => {
      if (err) {
        req.flash(
          'error_msg',
          'Incorrect or expired link! Please try again.'
        );
        res.redirect('/auth/login');
      }
      else {
        const { _id } = decodedToken;
        User.findById(_id, (err, user) => {
          if (err) {
            req.flash(
              'error_msg',
              'User with email ID does not exist! Please try again.'
            );
            res.redirect('/auth/login');
          }
          else {
            res.redirect(`/auth/reset/${_id}`);
          }
        });
      }
    });
  } else {
    console.log("Password reset error!");
  }
};

//------------ Reset Password ------------//
exports.resetPassword = (req, res) => {
  const { password, password2 } = req.body;
  const id = req.params.id;
  let errors = [];

  // Checking required fields
  if (!password || !password2) {
    req.flash(
      'error_msg',
      'Please enter all fields.'
    );
    res.redirect(`/auth/reset/${id}`);
  }
  // Checking password length
  else if (password.length < 8) {
    req.flash(
      'error_msg',
      'Password must be at least 8 characters.'
    );
    res.redirect(`/auth/reset/${id}`);
  }
  // Checking password mismatch
  else if (password != password2) {
    req.flash(
      'error_msg',
      'Passwords do not match.'
    );
    res.redirect(`/auth/reset/${id}`);
  } else {
    bcryptjs.genSalt(10, (err, salt) => {
      bcryptjs.hash(password, salt, (err, hash) => {
        if (err) throw err;
        password = hash;

        // Update password
        User.findByIdAndUpdate(
          { _id: id },
          { password },
          function (err, result) {
            if (err) {
              req.flash(
                'error_msg',
                'Error resetting password!'
              );
              res.redirect(`/auth/reset/${id}`);
            } else {
              req.flash(
                'success_msg',
                'Password reset successfully!'
              );
              res.redirect('/auth/login');
            }
          }
        );
      });
    });
  }
};
