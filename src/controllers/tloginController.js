const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const otpGenerator = require('otp-generator');
const Teacher = require('../models/teacher');

// Helper function to send OTP email
const sendOtpEmail = async (recipientEmail, otp) => {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: recipientEmail,
    subject: 'OTP Verification',
    text: `Your OTP code is: ${otp}. This code will expire in 3 minutes.`,
  };

  try {
    await transporter.sendMail(mailOptions);
    return { success: true };
  } catch (error) {
    console.error('Error sending OTP email:', error.message);
    return { success: false, message: 'Failed to send OTP' };
  }
};

// Login handler
exports.login = async (req, res) => {
  try {
    const { uname, password } = req.body;

    // Find teacher by email (uname)
    const teacher = await Teacher.findOne({ email: uname });
    if (!teacher) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    // Check if the teacher account is active
    if (teacher.status !== 'Active') {
      return res.status(403).json({ message: 'Your account is deactivated. Please contact an admin.' });
    }

    // Compare password
    const isMatch = await bcrypt.compare(password, teacher.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    // Generate OTP if required
    const otp = otpGenerator.generate(6, { digits: true, upperCase: false, specialChars: false });
    teacher.otp = otp;
    teacher.otpExpiresAt = new Date(Date.now() + 3 * 60 * 1000); // 3 minutes from now
    await teacher.save();

    // Send OTP email
    const emailResult = await sendOtpEmail(teacher.email, otp);
    if (!emailResult.success) {
      return res.status(500).json({ message: emailResult.message || 'Failed to send OTP' });
    }

    // Save session details
    req.session.userId = teacher._id;
    req.session.role = 'teacher';

    // Response includes whether OTP is required and if password has been changed
    return res.json({
      success: true,
      requireOtp: true, // Ensure this is true to trigger OTP modal
      passwordChanged: teacher.passwordChanged, // Indicates if password is already changed
    });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ message: 'Internal Server Error' });
  }
};

// OTP verification
exports.verifyOtp = async (req, res) => {
  try {
    const { otp } = req.body;

    if (!otp) {
      return res.status(400).json({ message: 'OTP is required' });
    }

    const teacher = await Teacher.findById(req.session.userId);
    if (!teacher) {
      return res.status(404).json({ message: 'Invalid Teacher' });
    }

    if (teacher.otp !== otp) {
      return res.status(400).json({ message: 'Invalid OTP' });
    }

    if (!teacher.otpExpiresAt || teacher.otpExpiresAt < new Date()) {
      return res.status(400).json({ message: 'OTP has expired. Please request a new one.' });
    }

    // Clear OTP for security
    teacher.otp = null;
    teacher.otpExpiresAt = null;
    await teacher.save();

    res.json({
      success: true,
      passwordChanged: teacher.passwordChanged, // Send whether the password is already changed
    });
  } catch (error) {
    console.error('OTP verification failed:', error.message);
    res.status(500).json({ message: 'Internal Server Error' });
  }
};

// Password change handler
exports.changePassword = async (req, res) => {
  try {
    const { newPassword } = req.body;

    if (!newPassword || newPassword.trim().length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters long.' });
    }

    const teacherId = req.session.userId;
    if (!teacherId) {
      return res.status(401).json({ message: 'Unauthorized access.' });
    }

    const teacher = await Teacher.findById(teacherId);
    if (!teacher) {
      return res.status(404).json({ message: 'Teacher not found.' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    teacher.password = hashedPassword;
    teacher.passwordChanged = true; // Set to true after password is changed
    teacher.otp = null;
    teacher.otpExpiresAt = null;

    await teacher.save();

    return res.json({ success: true, message: 'Password changed successfully.' });
  } catch (error) {
    console.error('Password change error:', error.message);
    res.status(500).json({ message: 'Internal Server Error' });
  }
};