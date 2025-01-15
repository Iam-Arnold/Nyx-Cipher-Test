const mongoose = require('mongoose');
var uniqueValidator = require('mongoose-unique-validator');
const bcrypt = require('bcryptjs');
const { CUSTOMER } = require('../config/constant');

//------------ User Schema ------------//
const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  role: { type: String, default: CUSTOMER },
  phone_number: { type: String, default: '' },
  verified: { type: Boolean, default: false },
  resetLink: { type: String, default: '' },
  cart_entry: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Cart' }],
  kyc_verified: { type: Boolean, default: false },
  address: { type: Object, default: null },
}, { timestamps: true });

UserSchema.plugin(uniqueValidator, { message: 'is already taken.' });

// Pre-save hook to hash password
UserSchema.pre('save', async function (next) {
  try {
    // Only hash the password if it is modified or new
    if (!this.isModified('password')) return next();

    // Salt and hash the password
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);

    next();
  } catch (error) {
    next(error);
  }
});

// Password comparison method
UserSchema.methods.comparePassword = async function (candidatePassword) {
  try {
    return await bcrypt.compare(candidatePassword, this.password);
  } catch (error) {
    throw error;
  }
};

UserSchema.methods.toProfileJSONFor = function () {
  return {
    username: this.username,
    email: this.email,
    role: this.role,
    phone_number: this.phone_number,
    verified: this.verified,
    resetLink: this.resetLink,
    cart_entry: this.cart_entry,
    kyc_verified: this.kyc_verified,
    address: this.address,
  };
};

const User = mongoose.model('User', UserSchema);

module.exports = User;
