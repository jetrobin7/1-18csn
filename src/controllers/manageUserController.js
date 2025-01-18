const Teacher = require('../models/teacher'); // Import Teacher model

// Function to render the manage_user.ejs page with all teachers
const renderManageUsers = async (req, res) => {
    try {
        const teachers = await Teacher.find(); // Fetch all teachers
        if (!teachers.length) {
            req.flash('info_msg', 'No teachers found.');
        }
        res.render('admin/manage_user', { teachers }); // Make sure this matches the filename exactly
    } catch (error) {
        req.flash('error_msg', 'Error retrieving teachers: ' + error.message);
        res.redirect('/admin/dashboard');
    }
};

// Function to update a teacher's status (active/inactive)
const updateTeacherStatus = async (req, res) => {
    const { id } = req.params; // Teacher ID from request params
    const { status } = req.body; // New status from request body

    const validStatuses = ['Active', 'Inactive']; // Valid statuses
    if (!validStatuses.includes(status)) {
        return res.status(400).json({ success: false, error: 'Invalid status' });
    }

    try {
        // Update the teacher's status in the database
        await Teacher.findByIdAndUpdate(id, { status });
        res.json({ success: true });
    } catch (error) {
        console.error('Error updating teacher status:', error);
        res.status(500).json({ success: false, error: 'Failed to update status' });
    }
};


// Function to fetch teacher count
const fetchTeacherCount = async (req, res) => {
    try {
        const teacherCount = await Teacher.countDocuments(); // Count the total teachers
        res.json({ count: teacherCount });
    } catch (error) {
        console.error('Error fetching teacher count:', error);
        res.status(500).json({ error: 'Failed to fetch teacher count' });
    }
};

module.exports = {
    renderManageUsers,
    updateTeacherStatus,
    fetchTeacherCount,
};
