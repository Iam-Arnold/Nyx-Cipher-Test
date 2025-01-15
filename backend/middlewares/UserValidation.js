const User = require('../models/User');

/**
 * Middleware for advanced user validation
 * - Checks if the email is unique
 * - Enforces a strong password policy
 */
const UserValidation = async (req, res, next) => {
    try {
        const { email, password } = req.body;

        // Email uniqueness check
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            const error = new Error(`The email ${email} is already registered. Please use a different email address or log in if you already have an account.`);
            error.httpStatus = 400;
            return next(error);
        }

        // Strong password policy validation
        const passwordPolicy = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        if (!passwordPolicy.test(password)) {
            const error = new Error('Password must be at least 8 characters long, include at least one uppercase letter, one lowercase letter, one number, and one special character.');
            error.httpStatus = 400;
            return next(error);
        }

        next();
    } catch (error) {
        console.error('Error in UserValidation middleware:', error);
        const customError = new Error('Internal server error. Please try again later.');
        customError.httpStatus = 500;
        next(customError);
    }
};

module.exports = UserValidation;
