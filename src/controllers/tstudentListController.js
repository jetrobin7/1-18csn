const Appointment = require('../models/appointment');

exports.getStudentList = async (req, res) => {
    try {
        // Check if the user is authenticated
        if (!req.user) {
            throw new Error('User is not authenticated. Ensure req.user is populated.');
        }

        // Get the teacher's ID
        const teacherId = req.user._id;

        // Get selected date or default to today
        const date = req.query.date || new Date().toISOString().split('T')[0];

        // Fetch appointments for the teacher on the specified date
        const appointments = await Appointment.find({
            teacherId: teacherId,
            appointmentDate: new Date(date),
        })
            .sort('appointmentTimeStart')
            .populate('studentId', 'givenName surname'); // Populate student details

        res.render('teacher/t_studentlist', { appointments, req }); // Pass appointments and req to EJS
    } catch (err) {
        console.error('Error retrieving student list:', err.message);
        res.status(500).send('Error retrieving student list');
    }
};

exports.updateAttendance = async (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.query;

        if (!['Present', 'Absent'].includes(status)) {
            return res.status(400).send('Invalid attendance status');
        }

        await Appointment.findByIdAndUpdate(id, { attendance: status });
        res.redirect('/teacher/student-list');
    } catch (err) {
        console.error('Error updating attendance:', err.message);
        res.status(500).send('Error updating attendance');
    }
};