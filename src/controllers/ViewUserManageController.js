const Teacher = require('../models/teacher');

exports.viewManageUsers = async (req, res) => {
    try {
        // Fetch all teachers
        const teachers = await Teacher.find();
        res.render('admin/ViewManageUser', { teachers });
    } catch (err) {
        console.error('Error fetching teachers:', err);
        res.status(500).send('Internal Server Error');
    }
};

exports.addTeacher = async (req, res) => {
    try {
        const { firstName, lastName, email, number, designation, therapyType } = req.body;
        
        const newTeacher = new Teacher({
            firstName,
            lastName,
            email,
            number,
            designation,
            therapyType,
            dateHired: new Date(),
            status: 'Active'
        });

        await newTeacher.save();
        res.redirect('/admin/manage-users');
    } catch (err) {
        console.error('Error adding teacher:', err);
        res.status(500).send('Internal Server Error');
    }
};

exports.editTeacher = async (req, res) => {
    try {
        const teacherId = req.params.id;
        const teacher = await Teacher.findById(teacherId);
        if (!teacher) {
            return res.status(404).send('Teacher not found');
        }

        res.render('admin/editTeacher', { teacher });
    } catch (err) {
        console.error('Error fetching teacher for edit:', err);
        res.status(500).send('Internal Server Error');
    }
};

exports.updateTeacher = async (req, res) => {
    try {
        const teacherId = req.params.id;
        const { firstName, lastName, email, number, designation, therapyType, status } = req.body;

        await Teacher.findByIdAndUpdate(teacherId, {
            firstName,
            lastName,
            email,
            number,
            designation,
            therapyType,
            status
        });

        res.redirect('/admin/manage-users');
    } catch (err) {
        console.error('Error updating teacher:', err);
        res.status(500).send('Internal Server Error');
    }
};

exports.deleteTeacher = async (req, res) => {
    try {
        const teacherId = req.params.id;
        await Teacher.findByIdAndDelete(teacherId);
        res.redirect('/admin/manage-users');
    } catch (err) {
        console.error('Error deleting teacher:', err);
        res.status(500).send('Internal Server Error');
    }
};
