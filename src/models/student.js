const mongoose = require('mongoose');

const studentSchema = new mongoose.Schema({
    csnNo: { type: String, required: true, unique: true },
    intakeDate: { type: Date, required: true },
    surname: { type: String, required: true },
    givenName: { type: String, required: true },
    middleName: { type: String },
    suffix: { type: String },
    gender: { type: String, required: true },
    dateOfBirth: { type: Date, required: true },
    age: { type: Number, required: true },
    district: { type: String },
    barangay: { type: String },
    completeAddress: { type: String, required: true },
    contactNumber: { type: String },
    emailAddress: { type: String },
    parentTatay: { type: String },
    trabahoTatay: { type: String },
    parentNanay: { type: String },
    trabahoNanay: { type: String },
    workingStatus: { type: String },
    incomeBracket: { type: String },
    familyMembers: { type: Number },
    benefits: { type: [String], default: [] }, // Array of strings
    schoolName: { type: String },
    gradeLevel: { type: String },
    schoolSchedule: { type: String },
    schoolDays: { type: [String], default: [] }, // Array of strings
    therapySchedule: { type: String },
    diagnosis: { type: [String], default: [] }, // Array of strings
    otherConditions: { type: String },
    assessmentDate: { type: Date },
    reassessmentDate: { type: Date },
    testingCenter: { type: String },
    pwdIdNo: { type: String },
    dateIssued: { type: Date },
    validity: { type: Date },
    consent: { type: Boolean, required: true }, // Boolean field
    photo: { type: String },
});


const Student = mongoose.model('Student', studentSchema);

module.exports = Student;
