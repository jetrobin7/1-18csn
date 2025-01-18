const Student = require('../models/student');
const Appointment = require('../models/appointment');

// Fetch all students
exports.getStudentProgress = async (req, res) => {
  try {
    const students = await Student.find({});
    res.render('admin/studentProgress', { students });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
};

// Fetch and render a specific student's progress details
exports.getStudentProgressDetails = async (req, res) => {
  try {
    const studentId = req.params.id;
    const student = await Student.findById(studentId);
    const appointments = await Appointment.find({ studentId });

    // Group appointments by category
    const therapySessions = appointments.reduce((acc, appointment) => {
      if (!acc[appointment.category]) {
        acc[appointment.category] = {
          typeOfTherapy: appointment.therapyType,
          teacher: appointment.teacherId,
          details: []
        };
      }
      acc[appointment.category].details.push({
        date: appointment.appointmentDate.toLocaleDateString(),
        time: `${appointment.appointmentTimeStart} - ${appointment.appointmentTimeEnd}`,
        status: appointment.attendance
      });
      return acc;
    }, {});

    res.render('admin/studentDetails', {
      student: {
        ...student.toObject(),
        therapySessions: Object.values(therapySessions)
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Server Error');
  }
};
