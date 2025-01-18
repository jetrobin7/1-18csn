const Student = require('../models/student'); // Import the student model
const Teacher = require('../models/teacher'); // Import the teacher model
const CalendarActivity = require('../models/calendaractivity'); // Import the calendar activity model

exports.renderDashboard = async (req, res) => {
  try {
    // Fetch the total number of students and teachers
    const students = await Student.find();
    const totalStudents = students.length;

    const teachers = await Teacher.find();
    const totalTeachers = teachers.length;

    // Fetch the first 5 non-completed activities from the database, sorted by date
    const activities = await CalendarActivity.find({ isCompleted: { $ne: true } }).sort({ date: 1 }).limit(5);

    // Send the data to the view
    res.render('./admin/dashboard', {
      totalStudents,
      totalTeachers,
      activities
    });
  } catch (error) {
    console.error('Error rendering dashboard:', error);
    res.status(500).send('Error rendering dashboard');
  }
};


// Helper function to calculate age distribution
function calculateAgeDistribution(students) {
  const maleCounts = [0, 0, 0, 0, 0];
  const femaleCounts = [0, 0, 0, 0, 0];

  students.forEach(student => {
    const age = new Date().getFullYear() - new Date(student.dateOfBirth).getFullYear();
    
    if (student.gender === 'Male') {
      if (age <= 5) maleCounts[0]++;
      else if (age <= 8) maleCounts[1]++;
      else if (age <= 13) maleCounts[2]++;
      else if (age <= 17) maleCounts[3]++;
      else if (age <= 25) maleCounts[4]++;
    } else if (student.gender === 'Female') {
      if (age <= 5) femaleCounts[0]++;
      else if (age <= 8) femaleCounts[1]++;
      else if (age <= 13) femaleCounts[2]++;
      else if (age <= 17) femaleCounts[3]++;
      else if (age <= 25) femaleCounts[4]++;
    }
  });

  return { maleCounts, femaleCounts };
}

// src/controllers/dashboardController.js
exports.addActivity = async (req, res) => {
  try {
    const { title, date, time, details } = req.body;

    // Combine date and time into a single Date object
    const eventDateTime = new Date(`${date}T${time}:00`);  // Format it as YYYY-MM-DDTHH:mm:ss

    const newActivity = new CalendarActivity({
      title,
      date: eventDateTime,
      time,  // Store the time as a string (HH:mm format)
      details,
    });

    await newActivity.save();

    // Send a response indicating success
    res.status(201).json(newActivity);
  } catch (error) {
    console.error('Error adding activity:', error);
    res.status(500).send('Error adding activity');
  }
};


// Mark activity as done
exports.markActivityDone = async (req, res) => {
  try {
    const activity = await CalendarActivity.findById(req.params.id);
    if (!activity) {
      return res.status(404).send('Activity not found');
    }

    activity.isCompleted = true;
    await activity.save();

    // Send a response indicating success
    res.status(200).send('Activity marked as done');
  } catch (error) {
    console.error('Error marking activity as done:', error);
    res.status(500).send('Error marking activity as done');
  }
};
