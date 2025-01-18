const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const superAdminSchema = new mongoose.Schema({
  first_name: { type: String, required: true },
  last_name: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  otp: { type: String, default: null }, // Field for storing OTP
  otpExpiresAt: { type: Date, default: null }, // Field for storing OTP expiration time
});

// Hash password before saving
superAdminSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Method to check if OTP is valid
superAdminSchema.methods.isOtpValid = function (otp) {
  return this.otp === otp && this.otpExpiresAt > new Date();
};

// Method to change password
superAdminSchema.methods.changePassword = async function (newPassword) {
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(newPassword, salt);
  await this.save();
};

const SuperAdmin = mongoose.model('SuperAdmin', superAdminSchema);
module.exports = SuperAdmin;
