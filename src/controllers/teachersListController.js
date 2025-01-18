const Appointment = require('../models/appointment');
const Teacher = require('../models/teacher');

const teachersListController = {
  // Fetch all teachers
  getTeacherList: async (req, res) => {
    try {
      const teachers = await Teacher.find().select('userId firstName lastName number therapyType');
      res.render('admin/teacherList', { teachers });
    } catch (error) {
      res.status(500).send('Error fetching teacher list');
    }
  },

  // Fetch appointments for a specific teacher
  getAppointmentsByTeacher: async (req, res) => {
    const { userId } = req.params;

    try {
      // Find the teacher by userId
      const teacher = await Teacher.findOne({ userId });
      if (!teacher) {
        return res.status(404).send('Teacher not found');
      }

      // Fetch appointments for the teacher
      const appointments = await Appointment.find({ teacherId: teacher._id }).populate('studentId');
      res.render('admin/appointmentsList', { teacher, appointments });
    } catch (error) {
      res.status(500).send('Error fetching appointments');
    }
  },
};

module.exports = teachersListController;
