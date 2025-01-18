const mongoose = require('mongoose');
const Student = require('../models/student');  // Assuming you have a Student model for database access

// Controller to fetch and render student details
const viewStudent = async (req, res) => {
  try {
    const studentId = req.params.id;  // Get the student ID from the route parameter
    
    // Check if the studentId is a valid ObjectId
    if (!mongoose.Types.ObjectId.isValid(studentId)) {
      return res.status(400).send('Invalid student ID');
    }

    // Fetch student data from the database by ID
    const student = await Student.findById(studentId);

    // If no student is found, return an error message
    if (!student) {
      return res.status(404).send('Student not found');
    }

    // Render the view_student template and pass the student data to it
    res.render('admin/view_student', {
      student: student,
    });
  } catch (error) {
    console.error('Error fetching student data:', error);
    res.status(500).send('Server error');
  }
};

module.exports = { viewStudent };