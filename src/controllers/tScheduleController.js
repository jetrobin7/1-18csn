const moment = require('moment');
const Appointment = require('../models/appointment');

exports.getTeacherSchedule = async (req, res) => {
    try {
        // Check if req.user exists
        if (!req.user) {
            throw new Error('User is not authenticated. Ensure req.user is populated.');
        }

        // Get the teacher's ID
        const teacherId = req.user._id;

        // Get selected date or default to the current date
        const selectedDate = req.query.selectedDate || moment().format('YYYY-MM-DD');
        const startOfWeek = moment(selectedDate).startOf('week').add(1, 'days'); // Start of the week (Monday)
        const endOfWeek = moment(selectedDate).endOf('week').subtract(1, 'days'); // End of the week (Friday)

        // Fetch appointments for the teacher for the selected week
        const appointments = await Appointment.find({
            teacherId: teacherId,
            appointmentDate: {
                $gte: startOfWeek.toDate(),
                $lte: endOfWeek.toDate(),
            },
        }).populate('studentId', 'givenName surname'); // Populate student details

        // Group appointments by day and time slot
        const groupedAppointments = {
            Monday: {},
            Tuesday: {},
            Wednesday: {},
            Thursday: {},
            Friday: {},
        };

        const uniqueTimeSlots = new Set(); // Set to hold unique time slots for the week

        appointments.forEach((appointment) => {
            const day = moment(appointment.appointmentDate).format('dddd'); // e.g., Monday, Tuesday
            const timeSlot = `${appointment.appointmentTimeStart} - ${appointment.appointmentTimeEnd}`;
            uniqueTimeSlots.add(timeSlot);

            if (!groupedAppointments[day][timeSlot]) {
                groupedAppointments[day][timeSlot] = [];
            }

            // Add student name to the corresponding time slot
            groupedAppointments[day][timeSlot].push({
                givenName: appointment.studentId?.givenName || 'Unknown',
                surname: appointment.studentId?.surname || 'Student',
            });
        });

        // Prepare date range for the display in the required format
        const weekDates = {
            Monday: moment(startOfWeek).add(0, 'days').format('dddd'), // "Monday"
            MondayDateOnly: moment(startOfWeek).add(0, 'days').format('MMMM D, YYYY'), // "December 23, 2024"
            Tuesday: moment(startOfWeek).add(1, 'days').format('dddd'),
            TuesdayDateOnly: moment(startOfWeek).add(1, 'days').format('MMMM D, YYYY'),
            Wednesday: moment(startOfWeek).add(2, 'days').format('dddd'),
            WednesdayDateOnly: moment(startOfWeek).add(2, 'days').format('MMMM D, YYYY'),
            Thursday: moment(startOfWeek).add(3, 'days').format('dddd'),
            ThursdayDateOnly: moment(startOfWeek).add(3, 'days').format('MMMM D, YYYY'),
            Friday: moment(startOfWeek).add(4, 'days').format('dddd'),
            FridayDateOnly: moment(startOfWeek).add(4, 'days').format('MMMM D, YYYY'),
        };

        // Convert Set to Array and sort time slots
        const sortedTimeSlots = Array.from(uniqueTimeSlots).sort();

        // Prepare data for the view
        const dateRangeDisplay = `${moment(startOfWeek).format('dddd, MMMM D, YYYY')} - ${moment(
            endOfWeek
        ).format('dddd, MMMM D, YYYY')}`;

        res.render('teacher/t_schedule', {
            dateRangeDisplay,
            weekDates,
            groupedAppointments,
            uniqueTimeSlots: sortedTimeSlots,
            appointments,
        });
    } catch (error) {
        console.error('Error fetching teacher schedule:', error.message);
        res.status(500).send('Internal Server Error');
    }
};
