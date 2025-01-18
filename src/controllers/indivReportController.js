const Student = require('../models/student'); // Import the Student model

exports.searchStudent = async (req, res) => {
  const { csnNumber } = req.query;

  try {
    // Search the student in the MongoDB database by CSN number
    const student = await Student.findOne({ csnNo: csnNumber }).lean(); // Use lean() for better performance if no updates are needed

    if (!student) {
      return res.render('admin/indivReport', {
        student: null,
        searchPerformed: true, // Indicate that a search was performed but no results were found
      });
    }

    // Render the page with the student's information
    res.render('admin/indivReport', {
      student, // Pass the student details to the view
      searchPerformed: true,
    });
  } catch (error) {
    console.error('Error searching for student:', error);
    res.status(500).send('An error occurred while searching for the student.');
  }
};

exports.viewStudentDetails = async (req, res) => {
    const { csnNumber } = req.query;
  
    try {
      // Find the student in the database
      const student = await Student.findOne({ csnNo: csnNumber }).lean();
  
      if (!student) {
        return res.status(404).send('Student not found');
      }
  
      // Render the new details page
      res.render('admin/indivReportDetails', { student });
    } catch (error) {
      console.error('Error retrieving student details:', error);
      res.status(500).send('An error occurred while fetching the student details.');
    }
  };
  