const Appointment = require('../models/appointment');
const nodemailer = require('nodemailer');
const Student = require('../models/student');
const Therapy = require('../models/therapy');
const Teacher = require('../models/teacher');

// 📝 **Render the Add Appointment Form (Teacher View)**
async function renderAddAppointmentForm(req, res) {
    const { csnNo } = req.query;

    try {
        // Fetch student details using CSN No.
        const student = await Student.findOne({ csnNo });
        const therapies = await Therapy.find({});
        const teachers = await Teacher.find({});

        res.render('teacher/t_add_an_appointment', {
            student,
            therapies,
            teachers,
        });
    } catch (error) {
        console.error('Error fetching appointment form data:', error);
        res.status(500).send('Internal Server Error');
    }
}

// 📝 **Create a New Appointment (Teacher View)**
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
        teacher, // Teacher's _id
        emailAddress,
    } = req.body;

    try {
        // 🔍 **Validate Student Existence**
        const student = await Student.findOne({ csnNo });
        if (!student) {
            req.flash('error_msg', 'Student not found');
            return res.redirect('/teacher/t_make_an_appointment');
        }

        // 🔍 **Validate Teacher Existence**
        const teacherDoc = await Teacher.findById(teacher);
        if (!teacherDoc) {
            req.flash('error_msg', 'Teacher not found');
            return res.redirect('/teacher/t_make_an_appointment');
        }

        // ⏳ **Check for Scheduling Conflicts**
        const conflictingAppointment = await Appointment.findOne({
            studentId: student._id,
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
            req.flash('error_msg', 'Scheduling conflict: Appointment time overlaps with another booking.');
            return res.redirect('/teacher/t_make_an_appointment');
        }

        // 📅 **Create the Appointment**
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
            teacherId: teacherDoc._id,
            emailAddress,
        });

        await appointment.save();

        // 📧 **Send Confirmation Email**
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
- Teacher: ${teacherDoc.name}

Thank you,
${teacherDoc.name}
Your Therapy Center`,
        };

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS,
            },
        });

        await transporter.sendMail(mailOptions);

        req.flash('success_msg', 'Appointment added and confirmation email sent successfully');
        res.redirect('/teacher/t_manage_appointment');
    } catch (error) {
        console.error('Error creating appointment:', error.message);
        req.flash('error_msg', 'Error creating appointment or sending confirmation email');
        res.redirect('/teacher/t_make_an_appointment');
    }
}

// 📑 **Export Controller Functions**
module.exports = {
    renderAddAppointmentForm,
    createAppointment,
};
