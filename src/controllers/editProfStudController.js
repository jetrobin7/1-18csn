const Student = require('../models/student');

// Show Edit Profile Form
exports.editProfileForm = async (req, res) => {
    try {
        const student = await Student.findById(req.params.id);
        if (!student) {
            return res.status(404).send("Student not found");
        }
        res.render('admin/editProfileStudent', { student });
    } catch (error) {
        console.error(error);
        res.status(500).send('Server Error');
    }
};

// Handle Edit Profile Update
exports.editProfile = async (req, res) => {
    try {
        const updatedData = req.body;
        const student = await Student.findByIdAndUpdate(req.params.id, updatedData, { new: true });
        if (!student) {
            return res.status(404).send("Student not found");
        }
        res.redirect(`/admin/student-profile/${student._id}`);
    } catch (error) {
        console.error(error);
        res.status(500).send('Server Error');
    }
};
