const moment = require('moment');
const Appointment = require('../models/appointment');

exports.getTeacherSchedule = async (req, res) => {
    try {
        // Get selected date or default to the current date
        const selectedDate = req.query.selectedDate || moment().format('YYYY-MM-DD');
        const startOfWeek = moment(selectedDate).startOf('week'); // Start of the week (Sunday)
        const endOfWeek = moment(selectedDate).endOf('week'); // End of the week (Saturday)

        // Fetch appointments for the selected week
        const appointments = await Appointment.find({
            appointmentDate: {
                $gte: startOfWeek.toDate(),
                $lte: endOfWeek.toDate(),
            }
        }).populate('teacherId', 'firstName lastName') // Populate teacher details
          .populate('studentId', 'givenName surname');

        // Group appointments by day and time slot
        const groupedAppointments = {
            Monday: {},
            Tuesday: {},
            Wednesday: {},
            Thursday: {},
            Friday: {},
        };

        const uniqueTimeSlots = new Set(); // Set to hold unique time slots for the week

        appointments.forEach(appointment => {
            const day = moment(appointment.appointmentDate).format('dddd'); // e.g., Monday, Tuesday
            const timeSlot = `${appointment.appointmentTimeStart} - ${appointment.appointmentTimeEnd}`;
            uniqueTimeSlots.add(timeSlot);

            if (!groupedAppointments[day][timeSlot]) {
                groupedAppointments[day][timeSlot] = [];
            }

            // Add teacher name to the corresponding time slot
            groupedAppointments[day][timeSlot].push(`${appointment.teacherId.firstName} ${appointment.teacherId.lastName}`);
        });

        // Prepare date range for the display
        const weekDates = {
            Monday: moment(startOfWeek).add(1, 'days').format('dddd'), // Weekday name
            MondayDateOnly: moment(startOfWeek).add(1, 'days').format('MMMM D, YYYY'), // Date in long format
            Tuesday: moment(startOfWeek).add(2, 'days').format('dddd'),
            TuesdayDateOnly: moment(startOfWeek).add(2, 'days').format('MMMM D, YYYY'),
            Wednesday: moment(startOfWeek).add(3, 'days').format('dddd'),
            WednesdayDateOnly: moment(startOfWeek).add(3, 'days').format('MMMM D, YYYY'),
            Thursday: moment(startOfWeek).add(4, 'days').format('dddd'),
            ThursdayDateOnly: moment(startOfWeek).add(4, 'days').format('MMMM D, YYYY'),
            Friday: moment(startOfWeek).add(5, 'days').format('dddd'),
            FridayDateOnly: moment(startOfWeek).add(5, 'days').format('MMMM D, YYYY'),
        };

        // Convert Set to Array and sort time slots
        const sortedTimeSlots = Array.from(uniqueTimeSlots).sort();

        // Prepare data for the view
        const dateRangeDisplay = `${moment(startOfWeek).format('dddd, MMMM D, YYYY')} - ${moment(endOfWeek).format('dddd, MMMM D, YYYY')}`;

        res.render('admin/teacher_schedule', {
            dateRangeDisplay,
            weekDates,
            groupedAppointments,
            uniqueTimeSlots: sortedTimeSlots,
            appointments,
        });
    } catch (error) {
        console.error('Error fetching teacher schedule:', error);
        res.status(500).send('Internal Server Error');
    }
};
