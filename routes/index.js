const express = require('express');
const router = express.Router();

// Controllers
const homeController = require('../src/controllers/homeController');
const superAdminController = require('../src/controllers/superAdminController');
const adminController = require('../src/controllers/adminController');
const teacherController = require('../src/controllers/teacherController');
const studentController = require('../src/controllers/studentController');
const dashboardController = require('../src/controllers/dashboardController');
const makeAppointmentController = require('../src/controllers/makeAppointmentController'); 
const tmakeAppointmentController = require('../src/controllers/tmakeAppointmentController'); 
const masterlistController = require('../src/controllers/masterlistController'); 
const manageUserController = require('../src/controllers/manageUserController');
const addAppointmentController = require('../src/controllers/addAppointmentController'); 
const manageAppointmentsController = require('../src/controllers/manageAppointmentsController');
const therapyController = require('../src/controllers/therapyController');
const viewAppointmentControllers = require('../src/controllers/viewAppointmentControllers');
const tloginController = require('../src/controllers/tloginController');
const tdashboardController = require('../src/controllers/tdashboardController'); 
const { viewStudent } = require('../src/controllers/viewStudentController');
const teacherScheduleController = require('../src/controllers/teacherScheduleController');
const tScheduleController = require('../src/controllers/tScheduleController');
const tappointmentController = require('../src/controllers/tappointmentController');
const tmanageAppointmentController = require('../src/controllers/tmanageAppointmentController');
const taddnewStudentController = require('../src/controllers/taddnewStudentController');
const teachersListController = require('../src/controllers/teachersListController');
const tStudentListController = require('../src/controllers/tstudentListController');
const genMasterlistReportController = require('../src/controllers/genMasterlistReportController');
const forgotPasswordController = require("../src/controllers/forgotPasController");
const editProfStudController = require('../src/controllers/editProfStudController');
const ViewUserManageController = require('../src/controllers/ViewUserManageController');
const indivReportController = require('../src/controllers/indivReportController');
const studProgController = require('../src/controllers/studProgController');

// Middleware
const { verifyToken, verifyTeacher } = require('../src/middleware/auth');

// Route to render the forgot password page
router.get('/admin/forgot_password', (req, res) => {
    res.render('admin/forgotPassword');
});

// Route to handle sending reset code (OTP)
router.post('/admin/forgot_password', forgotPasswordController.sendResetCode);

// Route to verify the reset code (OTP)
router.post('/admin/verify_reset_code', forgotPasswordController.verifyResetCode);

// Route to render the change password page
router.get('/admin/change_password', (req, res) => {
    res.render('admin/changePass');
});

// Route to handle the password change
router.post('/admin/change_password', forgotPasswordController.changePassword);

// Home route
router.get('/', homeController.renderHome);

// Teacher login routes
router.get('/tlogin', (_req, res) => {
    res.render('teacher/tlogin'); // Render the teacher login page
});
router.post('/tlogin', tloginController.login); // Handle login

router.get('/teacher/verifyotp', (_req, res) => {
    res.render('teacher/verifyotp');
});

// OTP verification route for teachers
router.post('/teacher/verifyotp', tloginController.verifyOtp); // Handle OTP verification

router.post('/tchange-password', tloginController.changePassword);

// Admin login page route (GET)
router.get('/adminlogin', (_req, res) => {
    res.render('admin/adminlogin');
});

// Admin login route (POST)
router.post('/adminlogin', adminController.login);

// OTP verification route (GET)
router.get('/verifyotp', (_req, res) => {
    res.render('admin/verifyotp');
});

// OTP verification route (POST)
router.post('/verifyotp', adminController.verifyOtp);

// Manage Users Routes
router.get('/admin/manage_user', verifyToken, manageUserController.renderManageUsers); // Route for managing users
router.patch('/user/:id/status', verifyToken, manageUserController.updateTeacherStatus); // Update teacher status
router.get('/api/teachers', verifyToken, manageUserController.fetchTeacherCount); // Fetch teacher count

// SuperAdmin signup route (GET)
router.get('/adminsignup', (_req, res) => {
    res.render('admin/adminsignup');
});

// SuperAdmin signup route (POST)
router.post('/adminsignup', superAdminController.signup);

// // Add Teacher page route (GET)
// router.get('/addteacher', verifyToken, (_req, res) => {
//     res.render('admin/addteacher', { userId: 'Generating...' });
// });

// Add Teacher route (POST)
router.get('/addteacher', verifyToken, teacherController.renderAddTeacherPage); // Correct GET route
router.post('/addteacher', verifyToken, teacherController.addTeacher);

router.get('/admin/masterlist', verifyToken, masterlistController.renderMasterlist); // GET: Masterlist page
router.get('/api/students', masterlistController.getStudentsData); // GET: API for student data

// Add New Student Routes
router.get('/admin/add_new_student', studentController.get); // Display add new student form
router.post('/admin/add_new_student', studentController.post); // Handle form submission

// Dashboard Route (GET)
router.get('/admin/dashboard', verifyToken, dashboardController.renderDashboard); // Render the dashboard page

// Teacher Dashboard Route (GET)
router.get('/teacher/tdashboard', verifyTeacher, tdashboardController.renderTeacherDashboard);

// Appointment Routes
router.get('/admin/a_make_an_appointment', makeAppointmentController.getStudents); // View students for appointment
router.get('/admin/a_make_an_appointment/add', addAppointmentController.renderAddAppointmentForm); // Use addAppointmentController
router.post('/admin/a_make_an_appointment/add', verifyToken, addAppointmentController.createAppointment); // Use addAppointmentController

// Manage Appointments Routes
router.get('/admin/manage_appointment', manageAppointmentsController.renderManageAppointments); // View all appointments
router.get('/admin/manage_appointment/search', manageAppointmentsController.searchAppointments); // Search appointments by CSN No. or Name
router.post('/admin/manage_appointment/reschedule', manageAppointmentsController.rescheduleAppointment);

// API route to fetch therapies
router.get('/api/therapies', therapyController.fetchTherapies);

// API route to add a new therapy
router.post('/api/therapies', therapyController.addTherapy);
router.get('/admin/types_of_therapy', verifyToken, therapyController.renderTypesOfTherapy);

// Route to display the list of students
router.get('/admin/view_appointment', viewAppointmentControllers.getStudentList);

// Route to display appointments for a specific student
router.get('/view_appointments/:studentId', viewAppointmentControllers.getStudentAppointments);


// Route to view student details
router.get('/admin/student_view/:id', viewStudent);

// Add a new activity
router.post('/api/activities', dashboardController.addActivity);

// Mark an activity as done
router.patch('/api/activities/:id/done', dashboardController.markActivityDone);


// Teacher Dashboard Route (GET)
router.get('/teacher/tdashboard', verifyTeacher, tdashboardController.renderTeacherDashboard);

router.get('/admin/teacher_schedule', teacherScheduleController.getTeacherSchedule);

// Route to display the teacher's schedule
router.get('/teacher/t_schedule', verifyTeacher, tScheduleController.getTeacherSchedule);

// Route to display the Student Appointment page
router.get('/teacher/t_make_an_appointment', tmakeAppointmentController.getStudents);

// Route to display the Add Appointment page
router.get('/teacher/t_make_an_appointment/add', tappointmentController.renderAddAppointmentForm);

// Route to handle the form submission for adding an appointment
router.post('/teacher/t_make_an_appointment/add', tappointmentController.createAppointment);

// Route to render the manage appointments page
router.get('/teacher/t_manage_appointment', tmanageAppointmentController.renderManageAppointments);
router.get('/teacher/t_manage_appointment/search', tmanageAppointmentController.searchAppointments); // Search appointments by CSN No. or Name
router.post('/teacher/t_manage_appointment/reschedule', tmanageAppointmentController.rescheduleAppointment);

// Render the "Add New Student" form
router.get('/t_add_new_student', taddnewStudentController.renderForm);

// Handle form submission
router.post('/t_add_new_student', taddnewStudentController.addStudent);

// Route to list all teachers
router.get('/admin/teachers', teachersListController.getTeacherList);

// Route to list appointments for a specific teacher
router.get('/admin/teachers/:userId/appointments', teachersListController.getAppointmentsByTeacher);

// Define routes
router.get('/teacher/student-list', verifyTeacher, tStudentListController.getStudentList);
router.get('/teacher/schedule', verifyTeacher, tScheduleController.getTeacherSchedule);
router.get('/teacher/attendance/:id', verifyTeacher, tStudentListController.updateAttendance);

//generate masterlist
router.post('/admin/generate_masterlist_report', genMasterlistReportController.generateMasterlistReport);

router.get('/admin/generate_masterlist_report', (req, res) => {
    res.redirect('/admin/genMasterlistReport');
});
// Render the form page
router.get('/admin/genMasterlistReport', (req, res) => {
    res.render('admin/genMasterlistReport'); // Ensure the path is correct
});


// Edit student profile form
router.get('/admin/edit-student/:id', editProfStudController.editProfileForm);

// Edit student profile update action
router.post('/admin/edit-student/:id', editProfStudController.editProfile);



// View manage users page
router.get('/admin/manage-users', ViewUserManageController.viewManageUsers);

// Add a new teacher
router.post('/admin/add-teacher', ViewUserManageController.addTeacher);


// Route for individual report
router.get('/admin/indivReport', (req, res) => {
    res.render('admin/indivReport', { student: null, searchPerformed: false });
  });
  
  router.get('/admin/indivReport/search', indivReportController.searchStudent);

// Route to view only the student's information
router.get('/admin/indivReport/details', indivReportController.viewStudentDetails);


// Route to fetch all students
router.get('/admin/studentProgress', studProgController.getStudentProgress);

// Route to fetch a specific student's progress details
router.get('/admin/studentProgress/:id', studProgController.getStudentProgressDetails);



module.exports = router;
