const Appointment = require('../models/appointment'); // Import Appointment model
const nodemailer = require('nodemailer'); // For sending emails

/**
 * Render the manage appointments page with all appointments.
 */
exports.renderManageAppointments = async (_req, res) => {
    try {
        const appointments = await Appointment.find({}); // Fetch all appointments
        res.render('admin/manage_appointment', { appointments }); // Render page with appointments
    } catch (error) {
        console.error('Error fetching appointments:', error.message);
        res.status(500).send('Server Error');
    }
};

exports.rescheduleAppointment = async (req, res) => {
    const { appointmentId, newDate, reason } = req.body;

    try {
        // Ensure the newDate is a valid date
        const validDate = new Date(newDate);
        if (isNaN(validDate)) {
            req.flash('error_msg', 'Invalid date format');
            return res.redirect('/admin/manage_appointment');
        }

        // Find the appointment to reschedule
        const appointment = await Appointment.findById(appointmentId);

        if (!appointment) {
            req.flash('error_msg', 'Appointment not found');
            return res.redirect('/admin/manage_appointment');
        }

        // Update appointment details
        appointment.appointmentDate = validDate;
        appointment.rescheduleReason = reason;
        await appointment.save();

        // Send email notification
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS,
            },
        });

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: appointment.emailAddress,
            subject: 'Appointment Rescheduled',
            text: `
Good day Mr./Ms. ${appointment.givenName} ${appointment.surname},

Your appointment has been rescheduled.

New Appointment Details:
- Date: ${validDate.toLocaleDateString()}
- Time: ${appointment.appointmentTimeStart} to ${appointment.appointmentTimeEnd}
- Therapy Type: ${appointment.therapyType}

Reason for Rescheduling:
${reason}

Thank you,
${appointment.teacher}
Your Therapy Center
            `,
        };

        try {
            await transporter.sendMail(mailOptions);
            req.flash('success_msg', 'Appointment rescheduled and email sent successfully');
        } catch (emailError) {
            console.error('Error sending email:', emailError.message);
            req.flash('error_msg', 'Appointment rescheduled, but email failed to send');
        }

        res.redirect('/admin/manage_appointment');
    } catch (error) {
        console.error('Error processing reschedule request:', error.message);
        req.flash('error_msg', 'Error processing reschedule request');
        res.redirect('/admin/manage_appointment');
    }
};
/**
 * Search for appointments by CSN No. or Name.
 */
exports.searchAppointments = async (req, res) => {
    const searchQuery = req.query.searchQuery;

    try {
        // Search for appointments by CSN No. or Name
        const appointments = await Appointment.find({
            $or: [
                { csnNo: { $regex: searchQuery, $options: 'i' } },
                { surname: { $regex: searchQuery, $options: 'i' } },
                { givenName: { $regex: searchQuery, $options: 'i' } },
            ],
        });

        res.render('admin/manage_appointment', { appointments });
    } catch (error) {
        console.error('Error searching appointments:', error.message);
        res.status(500).send('Server Error');
    }
};
