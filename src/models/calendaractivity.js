// src/models/calendaractivity.js
const mongoose = require('mongoose');

const CalendarActivitySchema = new mongoose.Schema({
  title: {
    type: String,
    required: true
  },
  date: {
    type: Date,
    required: true
  },
  time: {
    type: String,  // Store time as a string (HH:mm format)
    required: true
  },
  details: {
    type: String,
    required: false
  },
  isCompleted: {
    type: Boolean,
    default: false
  }
});

module.exports = mongoose.model('CalendarActivity', CalendarActivitySchema);
