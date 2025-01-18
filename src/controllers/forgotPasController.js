const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const otpGenerator = require('otp-generator');
const SuperAdmin = require('../models/SuperAdmin'); // Ensure this points to the correct model file

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

// Generate and send OTP to admin's email
exports.sendResetCode = async (req, res) => {
  const { uname } = req.body; // Email is passed as uname in the form

  try {
      // Perform case-insensitive search for the email
      const admin = await SuperAdmin.findOne({ email: { $regex: new RegExp(`^${uname}$`, 'i') } });

      if (!admin) {
          return res.status(404).json({ message: 'Email not found!' });
      }

      // Generate OTP for verification
      const otp = otpGenerator.generate(6, { digits: true, upperCase: false, specialChars: false });

      // Store OTP and expiration in the admin object
      admin.otp = otp;
      admin.otpExpiresAt = new Date(Date.now() + 3 * 60 * 1000); // 3 minutes from now
      await admin.save();

      // Send OTP to the admin's email
      const emailResult = await sendOtpEmail(admin.email, otp);
      if (!emailResult.success) {
          return res.status(500).json({ message: emailResult.message || 'Failed to send OTP' });
      }

      return res.status(200).json({ message: 'OTP sent successfully!' });
  } catch (error) {
      console.error('Error sending OTP:', error);
      res.status(500).json({ message: 'Error sending OTP!' });
  }
};


// Verify OTP
exports.verifyResetCode = async (req, res) => {
    const { otp, uname } = req.body;

    try {
        // Check if OTP is provided
        if (!otp) {
            return res.status(400).json({ message: 'OTP is required' });
        }

        // Find the admin using the provided OTP and email
        const admin = await SuperAdmin.findOne({ otp, email: uname });
        if (!admin) {
            return res.status(404).json({ message: 'Invalid OTP or email!' });
        }

        // Check if OTP has expired
        if (!admin.otp || !admin.otpExpiresAt || admin.otpExpiresAt < new Date()) {
            return res.status(400).json({ message: 'OTP has expired. Please request a new one.' });
        }

        // Ensure the OTP is only used once and clear OTP fields for security
        admin.otp = null;
        admin.otpExpiresAt = null;
        await admin.save();

        res.json({
            success: true,
            message: 'OTP verified successfully. You can now proceed to reset your password.',
        });
    } catch (error) {
        console.error('Error verifying OTP:', error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
};

// Change Password
exports.changePassword = async (req, res) => {
    const { uname, newPassword, confirmPassword } = req.body;

    if (newPassword !== confirmPassword) {
        return res.status(400).json({ message: 'Passwords do not match!' });
    }

    try {
        const admin = await SuperAdmin.findOne({ email: uname });
        if (!admin) {
            return res.status(404).json({ message: 'User not found!' });
        }

        // Update the admin's password (hashed for security)
        admin.password = await bcrypt.hash(newPassword, 10); // Hashing the password
        await admin.save();

        res.status(200).json({ message: 'Password updated successfully!' });
    } catch (error) {
        console.error('Error updating password:', error);
        res.status(500).json({ message: 'Error updating password!' });
    }
};
