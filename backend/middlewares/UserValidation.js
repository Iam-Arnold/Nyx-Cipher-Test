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
            return res.status(400).json({
                success: false,
                message: 'Email is already registered. Please use a different email.',
            });
        }

        // Strong password policy validation
        const passwordPolicy = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
        if (!passwordPolicy.test(password)) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 8 characters long, include an uppercase letter, a lowercase letter, a number, and a special character.',
            });
        }

        next();
    } catch (error) {
        console.error('Error in UserValidation middleware:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error. Please try again later.',
        });
    }
};

module.exports = UserValidation;
