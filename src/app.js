const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const session = require('express-session');
const flash = require('connect-flash');
const passport = require('passport');
require('dotenv').config();

const app = express();

// Import routes and configurations
const indexRouter = require('../routes/index'); // Adjust the path based on your structure
const connectDB = require('../config/dbConnection'); // MongoDB connection file
require('../config/passport')(passport); // Passport.js configuration

// Connect to MongoDB
connectDB();

// Middleware for parsing request bodies
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(flash());

// Set static files location
app.use(express.static(path.join(__dirname, '../public')));

// Set EJS as the view engine
app.set('views', path.join(__dirname, 'src/views'));
app.set('view engine', 'ejs');

// Define the location for the views folder
app.set('views', path.join(__dirname, './views'));

// Define the path for partials
app.locals.partials = path.join(__dirname, 'views', 'partials'); // Adjust the path if needed

// Session middleware
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'ndZfIHZQL36053up', // Replace with your .env secret
    resave: false,
    saveUninitialized: true,
    cookie: {
      secure: false, // Set to true in production with HTTPS
      maxAge: 60 * 60 * 1000, // Optional: Set session expiration time (1 hour)
    },
  })
);

// Initialize Passport.js for authentication
app.use(passport.initialize());
app.use(passport.session());

// Use the main router
app.use('/', indexRouter);

// Global error handler for debugging
app.use((err, req, res, next) => {
  console.error('Global Error Handler:', err.stack);
  res.status(500).json({ message: 'Internal Server Error', error: err.message });
});

// Admin Logout route
app.get('/user/alogout', (req, res) => {
  req.logout((err) => {
      if (err) {
          return next(err);
      }
      req.flash('success_msg', 'You are logged out successfully');
      res.redirect('/adminlogin'); // Redirect to admin login page after logout
  });
});

// Teacher Logout route
app.get('/teacher/tlogout', (req, res) => {
  req.logout((err) => {
      if (err) {
          return next(err);
      }
      req.flash('success_msg', 'You are logged out successfully');
      res.redirect('/tlogin'); // Redirect to teacher login page after logout
  });
});


module.exports = app;