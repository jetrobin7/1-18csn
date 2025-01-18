const Appointment = require('../models/appointment');
const nodemailer = require('nodemailer');
const Student = require('../models/student');
const Therapy = require('../models/therapy');
const Teacher = require('../models/teacher');

// Function to render the form for adding an appointment
async function renderAddAppointmentForm(req, res) {
    const { csnNo } = req.query;

    try {
        const student = await Student.findOne({ csnNo });
        const therapies = await Therapy.find({});
        const teachers = await Teacher.find({});

        res.render('admin/add_an_appointment', {
            student,
            therapies,
            teachers,
        });
    } catch (error) {
        console.error("Error fetching data:", error);
        res.status(500).send("Internal Server Error");
    }
}

// Function to handle appointment creation
async function createAppointment(req, res) {
    const {
        csnNo,
        surname,
        givenName,
        middleName,
        gender,
        appointmentDate,
        appointmentTimeStart,
        appointmentTimeEnd,
        therapyType,
        category,
        teacher,  // This should be teacher's _id (ObjectId)
        emailAddress,
    } = req.body;

    try {
        // Fetch the student ID using the provided CSN number
        const student = await Student.findOne({ csnNo });
        if (!student) {
            req.flash('error_msg', 'Student not found');
            return res.redirect('/admin/a_make_an_appointment');
        }

        // Fetch the teacher ID by the provided teacher name or other identifier
        const teacherDoc = await Teacher.findById(teacher);
        if (!teacherDoc) {
            req.flash('error_msg', 'Teacher not found');
            return res.redirect('/admin/a_make_an_appointment');
        }

        // Conflict check for overlapping appointments
        const conflictingAppointment = await Appointment.findOne({
            studentId: student._id, // Use the studentId for conflicts
            appointmentDate,
            $or: [
                {
                    appointmentTimeStart: { $lt: appointmentTimeEnd },
                    appointmentTimeEnd: { $gt: appointmentTimeStart },
                },
                {
                    appointmentTimeStart: { $gte: appointmentTimeStart, $lt: appointmentTimeEnd },
                },
            ],
        });

        if (conflictingAppointment) {
            req.flash('error', 'Scheduling conflict: You already set an appointment with the student');
            return res.redirect('/admin/a_make_an_appointment');
        }

        // Scheduling logic for a new appointment
        const appointment = new Appointment({
            studentId: student._id, 
            csnNo,
            surname,
            givenName,
            middleName,
            gender,
            appointmentDate,
            appointmentTimeStart,
            appointmentTimeEnd,
            therapyType,
            category,
            teacherId: teacherDoc._id, // Save the teacherId
            emailAddress,
        });

        await appointment.save();

        // Send scheduling confirmation email
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: emailAddress,
            subject: 'Appointment Confirmation',
            text: `Good day Mr./Ms. ${givenName} ${surname},

Your appointment has been successfully scheduled.

Details:
- Date: ${appointmentDate}
- Time: ${appointmentTimeStart} to ${appointmentTimeEnd}
- Therapy Type: ${therapyType}
- Teacher: ${teacherDoc.name}  <!-- Use teacher's name here -->

Thank you,
${teacherDoc.name}
Your Therapy Center`,
        };

        // Send email notification
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS,
            },
        });

        await transporter.sendMail(mailOptions);

        req.flash('success_msg', 'Appointment added and email sent successfully');
        res.redirect('/admin/manage_appointment');
    } catch (error) {
        console.error('Error creating appointment:', error.message);
        req.flash('error_msg', 'Error creating appointment or sending email');
        res.redirect('/admin/a_make_an_appointment');
    }
}


module.exports = {
    renderAddAppointmentForm,
    createAppointment
};
