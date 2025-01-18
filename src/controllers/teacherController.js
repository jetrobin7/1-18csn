const Teacher = require('../models/teacher');
const Therapy = require('../models/therapy');
const bcrypt = require('bcrypt');

const renderAddTeacherPage = async (req, res) => {
    try {
        // Fetch all therapies from the database
        const therapies = await Therapy.find();

        // Generate a unique user ID
        const userId = await generateUserId();

        // Render the addteacher.ejs page with therapies and userId
        res.render('admin/addteacher', { therapies, userId });
    } catch (error) {
        console.error(error);
        req.flash('error_msg', 'Error loading the Add Teacher page.');
        res.redirect('/admin/manage_user');
    }
};

// Generate unique employee ID (e.g., csn001)
const generateUserId = async () => {
    const lastTeacher = await Teacher.findOne().sort({ userId: -1 });
    if (!lastTeacher) return 'CSN001';
    const lastId = parseInt(lastTeacher.userId.substring(3), 10);
    const newId = lastId + 1;
    return `CSN${newId.toString().padStart(3, '0')}`;
};


const addTeacher = async (req, res) => {
    try {
        const { lastName, firstName, middleInitial, suffix, number, email, dateHired, designation, therapyType } = req.body;

        // Generate userId
        const userId = await generateUserId();

        // Use default password
        const defaultPassword = 'csn.Pque001';
        const hashedPassword = await bcrypt.hash(defaultPassword, 10);

        const teacher = new Teacher({
            lastName,
            firstName,
            middleInitial,
            suffix,
            number,
            email,
            password: hashedPassword,
            userId,
            dateHired: new Date(dateHired),
            designation,
            therapyType, // Save the selected therapyType
        });

        await teacher.save();
        req.flash('success_msg', 'Teacher added successfully');
        res.redirect('/admin/manage_user');
    } catch (error) {
        console.error(error);
        req.flash('error_msg', 'Failed to add teacher');
        res.redirect('/admin/addteacher');
    }
};


module.exports = { addTeacher, renderAddTeacherPage };
