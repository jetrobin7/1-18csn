const mongoose = require('mongoose');

const teacherSchema = new mongoose.Schema({
  lastName: { type: String, required: true },
  firstName: { type: String, required: true },
  middleInitial: { type: String },
  suffix: { type: String },
  number: { type: String },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  userId: { type: String, required: true, unique: true },
  dateHired: { type: Date, required: true },
  designation: { type: String, required: true },
  therapyType: { type: String, required: true }, // Single field for therapy type
  status: { type: String, enum: ['Active', 'Inactive'], default: 'Active' },
  otp: { type: String, default: null }, // Field for storing OTP
  otpExpiresAt: { type: Date, default: null }, // Field for storing OTP expiration time
  passwordChanged: { type: Boolean, default: false }, // New field
});

const Teacher = mongoose.model('Teacher', teacherSchema);

module.exports = Teacher;
