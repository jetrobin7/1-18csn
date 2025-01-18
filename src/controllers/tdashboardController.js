const Student = require('../models/student'); // Assuming you have a Student model for database interaction

// Render the Teacher Dashboard
exports.renderTeacherDashboard = async (req, res) => {
    try {
        // Fetch the list of new students from the database (replace logic with actual implementation)
        const newStudents = await Student.find({ isNew: true }).sort({ createdAt: -1 }).limit(10);

        res.render('teacher/tdashboard', {
            newStudents,
        });
    } catch (error) {
        console.error('Error fetching data for Teacher Dashboard:', error);
        res.status(500).send('Internal Server Error');
    }
};
