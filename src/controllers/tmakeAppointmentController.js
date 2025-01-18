const Appointment = require('../models/appointment'); // Import Appointment model
const Student = require('../models/student'); // Import Student model
const Therapy = require('../models/therapy');
const Teacher = require('../models/teacher');

// Controller for handling the "Make Appointment" functionality

// Controller function to get all students for viewing appointments
exports.getStudents = async (_req, res) => {
    try {
        // Fetch all students, could include some filter based on role or access rights
        const students = await Student.find().sort({ lastname: 1 }); // Sort students by last name
        res.render('teacher/t_make_an_appointment', { students }); // Render the page with students list
    } catch (error) {
        console.error("Error fetching students:", error);
        res.status(500).send("Error fetching students for appointment.");
    }
};

// Controller function to render the Add Appointment form with pre-filled student info
exports.addAppointment = async (req, res) => {
    try {
        // Fetch student details from the database using the CSN number passed as a query parameter
        const { csnNo, emailAddress } = req.query;
        
        if (!csnNo) {
            return res.status(400).send("CSN number is required.");
        }

        const student = await Student.findOne({ csnNo });
        
        if (!student) {
            return res.status(404).send("Student not found.");
        }

       // Pass email and other student details to the form
       res.render('teacher/add_appointment', {
        student: {
            ...student.toObject(),
            emailAddress: emailAddress || student.emailAddress // Use email from query or database
        }
    });
        } catch (error) {
            console.error("Error fetching student details:", error);
            res.status(500).send("Error fetching student details for appointment.");
        }
    };

// Controller function to handle form submission for creating a new appointment
exports.createAppointment = async (req, res) => {
    const {
        csnNo,
        lastname,
        firstname,
        middleName,
        appointmentDate,
        appointmentTimeStart,
        appointmentTimeEnd,
        therapyType,
        category,
        teacher,
        emailAddress
    } = req.body;

    try {
        // Conflict check for same date and overlapping times
        const conflictingAppointment = await Appointment.findOne({
            csnNo,
            appointmentDate,
            $or: [
                { 
                    appointmentTimeStart: { $lt: appointmentTimeEnd },
                    appointmentTimeEnd: { $gt: appointmentTimeStart }
                },
                { 
                    appointmentTimeStart: { $gte: appointmentTimeStart, $lt: appointmentTimeEnd }
                }
            ]
        });

        if (conflictingAppointment) {
            req.flash('error', 'Scheduling conflict: The selected time overlaps with another appointment on the same day.');
            return res.redirect('/teacher/t_make_an_appointment');
        }

        // Create a new appointment
        const newAppointment = new Appointment({
            csnNo,
            surname: lastname,
            givenName: firstname,
            middleName,
            appointmentDate,
            appointmentTimeStart,
            appointmentTimeEnd,
            therapyType,
            category,
            teacher,
            emailAddress
        });

        await newAppointment.save();

        req.flash('success', 'Appointment added successfully');
        res.redirect('/teacher/t_make_an_appointment');
    } catch (error) {
        console.error('Error adding appointment:', error.message);
        req.flash('error', 'Failed to add appointment');
        res.redirect('/teacher/t_make_an_appointment');
    }
};
