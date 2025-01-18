
const Student = require('../models/student'); // Ensure this points to your student model

module.exports = {
    renderForm: (req, res) => {
        res.render('teacher/t_add_new_student');
    },

    addStudent: async (req, res) => {
        try {
            const {
                csnNo, inTakeDate, surname, givenName, middleName, gender, dob, age,
                district, brgy, completeAddress, contactNumber, parentGuardian,
                trabahoNgMagulang, workingStatus, incomeBracket, familyMembers,
                benefitsMemberships, schoolName, gradeLevel, schoolHours,
                schoolDays, preferredSchedule, diagnosis, otherConditions,
                assessmentDate, assessmentSubmitted, testingCenter, intervention,
                pwdIdNo, dateIssued, validity,
            } = req.body;

            const photo = req.file?.filename; // Assuming multer is used for file upload

            // Create new student entry
            const newStudent = new Student({
                csnNo,
                inTakeDate,
                surname,
                givenName,
                middleName,
                gender,
                dob,
                age,
                district,
                brgy,
                completeAddress,
                contactNumber,
                parentGuardian,
                trabahoNgMagulang,
                workingStatus,
                incomeBracket,
                familyMembers,
                benefitsMemberships,
                schoolName,
                gradeLevel,
                schoolHours,
                schoolDays,
                preferredSchedule,
                diagnosis,
                otherConditions,
                assessmentDate,
                assessmentSubmitted,
                testingCenter,
                intervention,
                pwdIdNo,
                dateIssued,
                validity,
                photo,
            });

            await newStudent.save();
            res.redirect('/t_add_new_student'); // Redirect or show a success page
        } catch (error) {
            console.error(error);
            res.status(500).send('Server Error');
        }
    },
};
