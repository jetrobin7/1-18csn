const mongoose = require('mongoose');

const therapySchema = new mongoose.Schema({
    csnCourseCode: { type: String, required: true, unique: true }, // CSN formatted code
    name: { type: String, required: true }, // Name of the therapy
    description: { type: String, required: true }, // Description of the therapy
});

const Therapy = mongoose.model('Therapy', therapySchema);

module.exports = Therapy;
