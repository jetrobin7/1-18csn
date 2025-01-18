const Student = require('../models/student'); // Assuming you have a Student model
const Appointment = require('../models/appointment'); // Assuming you have an Appointment model

// Function to render the list of students with pagination
exports.getStudentList = async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1; // Get current page from query params, default to 1
        const limit = 15; // Number of students per page
        const skip = (page - 1) * limit;

        // Fetch students with pagination
        const students = await Student.find().sort({ name: 1 }).skip(skip).limit(limit);

        // Get the total count of students
        const totalStudents = await Student.countDocuments();
        const totalPages = Math.ceil(totalStudents / limit);

        res.render('admin/view_appointment', { 
            students, 
            currentPage: page, 
            totalPages 
        });
    } catch (error) {
        console.error('Error fetching student list:', error);
        res.status(500).send('Internal Server Error');
    }
};

// Function to render appointments for a specific student
exports.getStudentAppointments = async (req, res) => {
    const studentId = req.params.studentId;
    try {
        const student = await Student.findById(studentId);
        if (!student) {
            return res.status(404).send('Student not found');
        }

        const appointments = await Appointment.find({ student: studentId }).sort({ date: 1 });
        res.render('admin/view_student_appointments', { student, appointments });
    } catch (error) {
        console.error('Error fetching student appointments:', error);
        res.status(500).send('Internal Server Error');
    }
};

