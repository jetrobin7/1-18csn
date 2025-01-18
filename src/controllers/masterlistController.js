const Student = require('../models/student'); // Import the Student model

// Controller to render the masterlist page
exports.renderMasterlist = async (req, res) => {
    try {
        // Fetch all students sorted by csnNo
        const students = await Student.find().sort({ csnNo: 1 });
        res.render('admin/masterlist', { students }); // Ensure you have 'admin/masterlist.ejs'
    } catch (error) {
        console.error('Error fetching students:', error);
        req.flash('error_msg', 'An error occurred while fetching the masterlist.');
        res.redirect('/admin/dashboard'); // Redirect to dashboard or an appropriate page
    }
};

// API to fetch student data for analytics or external use
exports.getStudentsData = async (req, res) => {
    try {
        // Fetch students with only required fields
        const students = await Student.find({}, 'dateOfBirth gender');
        res.json(students);
    } catch (error) {
        console.error('Error fetching student data:', error);
        res.status(500).json({ error: 'Failed to fetch students' });
    }
};
