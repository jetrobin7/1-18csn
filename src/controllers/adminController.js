const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const otpGenerator = require('otp-generator');
const SuperAdmin = require('../models/SuperAdmin');

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

    // Check if admin exists with the provided email
    const admin = await SuperAdmin.findOne({ email: uname });
    if (!admin) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    // Compare the provided password with the stored hashed password
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    // Generate OTP for verification
    const otp = otpGenerator.generate(6, { digits: true, upperCase: false, specialChars: false });

    // Store OTP and expiration in admin object
    admin.otp = otp;
    admin.otpExpiresAt = new Date(Date.now() + 3 * 60 * 1000); // 3 minutes from now
    await admin.save();

    // Send OTP to the admin's email
    const emailResult = await sendOtpEmail(admin.email, otp);
    if (!emailResult.success) {
      return res.status(500).json({ message: emailResult.message || 'Failed to send OTP' });
    }

    // Store the admin user ID in the session (no token, purely session-based)
    req.session.userId = admin._id;

    return res.json({
      success: true,
      message: 'Login successful. An OTP has been sent to your email for verification.',
    });
  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ message: 'Internal Server Error' });
  }
};

// OTP verification handler
exports.verifyOtp = async (req, res) => {
  try {
    const { otp } = req.body;

    // Check if OTP is provided
    if (!otp) {
      return res.status(400).json({ message: 'OTP is required' });
    }

    // Find the admin using the provided OTP
    const admin = await SuperAdmin.findOne({ otp });
    if (!admin) {
      return res.status(404).json({ message: 'Invalid OTP' });
    }

    // Check if OTP has expired
    if (!admin.otp || !admin.otpExpiresAt || admin.otpExpiresAt < new Date()) {
      return res.status(400).json({ message: 'OTP has expired. Please request a new one.' });
    }

    // Ensure the OTP is only used once and clear OTP fields for security
    admin.otp = null;
    admin.otpExpiresAt = null;
    await admin.save();

    // Set session userId to indicate that the user is authenticated
    req.session.userId = admin._id;

    res.json({
      success: true,
      message: 'OTP verified successfully. You are now logged in.',
    });
  } catch (error) {
    console.error('OTP verification failed:', error.message);
    res.status(500).json({ message: 'Internal Server Error' });
  }
};
