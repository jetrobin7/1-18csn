const Student = require('../models/student'); // Import your Student model
const multer = require('multer');
const path = require('path');

// Set up Multer for file uploads
const storage = multer.diskStorage({
    destination: function (_req, _file, cb) {
        cb(null, 'uploads/'); // Folder where photos will be stored
    },
    filename: function (_req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname)); // Append timestamp to filename
    }
});

const upload = multer({ storage: storage });

// Function to generate a unique CSN number
async function generateCSN(intakeYear) {
    let csnNo = `${intakeYear}-CSN-000-01`; // Default CSN with intake year
    let exists = true;
    let counter = 1;

    while (exists) {
        const studentWithSameCsn = await Student.findOne({ csnNo: csnNo });
        if (studentWithSameCsn) {
            counter++;
            csnNo = `${intakeYear}-CSN-000-${counter.toString().padStart(2, '0')}`;
        } else {
            exists = false; // No duplicate found
        }
    }

    return csnNo;
}

// Controller to display the add new student form
exports.get = async (req, res) => {
    try {
        const currentYear = new Date().getFullYear();
        const csnNo = await generateCSN(currentYear); // Generate CSN number for the current year

        res.render('admin/add_new_student', { csnNo }); // Adjusted path to include 'admin'
    } catch (error) {
        console.error('Error fetching the CSN number:', error);
        req.flash('error_msg', 'Unable to fetch CSN number.');
        res.redirect('/error'); // Redirect to an error page or back to the form
    }
};

// Controller to handle form submission for adding a new student
exports.post = [
    upload.single('photo'),
    async (req, res) => {
        try {
            const intakeYear = new Date(req.body.intakeDate).getFullYear();
            const csnNo = await generateCSN(intakeYear);

            const newStudent = new Student({
                csnNo: csnNo,
                intakeDate: req.body.intakeDate,
                surname: req.body.surname,
                givenName: req.body.givenName,
                middleName: req.body.middleName,
                suffix: req.body.suffix,
                gender: req.body.gender,
                dateOfBirth: req.body.dateOfBirth,
                age: req.body.age,
                district: req.body.district,
                barangay: req.body.barangay,
                completeAddress: req.body.completeAddress,
                contactNumber: req.body.contactNumber,
                emailAddress: req.body.emailAddress,
                parentTatay: req.body.parentTatay,
                trabahoTatay: req.body.trabahoTatay,
                parentNanay: req.body.parentNanay,
                trabahoNanay: req.body.trabahoNanay,
                workingStatus: req.body.workingStatus,
                incomeBracket: req.body.incomeBracket,
                familyMembers: req.body.familyMembers,
                benefits: req.body.benefits || [], // Array from form
                schoolName: req.body.schoolName,
                gradeLevel: req.body.gradeLevel,
                schoolSchedule: req.body.schoolSchedule,
                schoolDays: req.body.schoolDays || [], // Array from form
                therapySchedule: req.body.therapySchedule,
                diagnosis: req.body.diagnosis || [], // Array from form
                otherConditions: req.body.otherConditions,
                assessmentDate: req.body.assessmentDate,
                reassessmentDate: req.body.reassessmentDate,
                testingCenter: req.body.testingCenter,
                pwdIdNo: req.body.pwdIdNo,
                dateIssued: req.body.dateIssued,
                validity: req.body.validity,
                consent: req.body.consent === 'Yes', // Convert "Yes" to Boolean
                photo: req.file ? req.file.filename : null,
            });

            await newStudent.save();
            req.flash('success_msg', 'Student added successfully!');
            res.redirect('/admin/masterlist');
        } catch (error) {
            console.error('Error adding new student:', error);
            req.flash('error_msg', 'An error occurred while adding the student.');
            res.redirect('/admin/add_new_student');
        }
    },
];

