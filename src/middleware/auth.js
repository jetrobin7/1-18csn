const SuperAdmin = require('../models/SuperAdmin');
const Teacher = require('../models/teacher');

// Middleware to verify general user token (SuperAdmin)
exports.verifyToken = async (req, res, next) => {
  try {
    // Check if the session contains a valid userId
    if (!req.session || !req.session.userId) {
      return res.status(401).json({ message: 'User not authenticated' });
    }

    // Fetch the user (SuperAdmin) from the database
    const user = await SuperAdmin.findById(req.session.userId);
    if (!user) {
      return res.status(401).json({ message: 'Invalid User' });
    }

    // Attach user to the request object for downstream use
    req.user = user;
    next();
  } catch (error) {
    console.error('User authentication failed:', error.message);
    res.status(403).json({ message: 'Authentication failed', error: error.message });
  }
};

// Middleware to verify teacher token
exports.verifyTeacher = async (req, res, next) => {
  try {
    // Check if the session contains a valid userId and role is teacher
    if (!req.session || !req.session.userId || req.session.role !== 'teacher') {
      return res.status(401).json({ message: 'Teacher not authenticated' });
    }

    // Fetch the teacher from the database
    const teacher = await Teacher.findById(req.session.userId);
    if (!teacher) {
      return res.status(401).json({ message: 'Invalid Teacher' });
    }

    // Attach teacher to the request object for downstream use
    req.user = teacher;
    next();
  } catch (error) {
    console.error('Teacher authentication failed:', error.message);
    res.status(500).json({ message: 'Authentication failed', error: error.message });
  }
};