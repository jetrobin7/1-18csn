const mongoose = require('mongoose');

const appointmentSchema = new mongoose.Schema({
    studentId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'Student', // Reference the Student model
        required: true 
    },
    teacherId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'Teacher', 
        required: true 
    },
    csnNo: { type: String, required: true },
    surname: { type: String, required: true },
    givenName: { type: String, required: true },
    middleName: { type: String },
    gender: { type: String, required: true },
    appointmentDate: { type: Date, required: true },
    appointmentTimeStart: { type: String, required: true },
    appointmentTimeEnd: { type: String, required: true },
    therapyType: { type: String, required: true },
    category: { type: String, required: true },
    emailAddress: { type: String, required: true },
    attendance: { type: String, enum: ['Present', 'Absent', 'Pending'], default: 'Pending' },
    rescheduleReason: { type: String }, // Optional: Reason for rescheduling
    rescheduleDate: { type: Date },    // Optional: New appointment date after rescheduling
}, { timestamps: true });


module.exports = mongoose.model('Appointment', appointmentSchema);