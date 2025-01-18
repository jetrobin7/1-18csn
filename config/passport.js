const LocalStrategy = require('passport-local').Strategy;
const SuperAdmin = require('../src/models/SuperAdmin'); // Adjust the path as needed
const Teacher = require('../src/models/teacher'); // Add the Teacher model path
const bcrypt = require('bcrypt');

module.exports = (passport) => {
  // Configure local strategy for SuperAdmin
  passport.use(
    new LocalStrategy(
      { usernameField: 'email' }, // Specify the field used for authentication
      async (email, password, done) => {
        try {
          // Find the admin by email
          const admin = await SuperAdmin.findOne({ email });
          if (!admin) {
            return done(null, false, { message: 'Email not registered' });
          }

          // Match password
          const isMatch = await bcrypt.compare(password, admin.password);
          if (!isMatch) {
            return done(null, false, { message: 'Incorrect password' });
          }

          // Success
          return done(null, admin);
        } catch (err) {
          return done(err);
        }
      }
    )
  );

  // Serialize user to store in session for SuperAdmin
  passport.serializeUser((admin, done) => {
    done(null, admin.id);
  });

  // Deserialize user to retrieve from session for SuperAdmin
  passport.deserializeUser(async (id, done) => {
    try {
      const admin = await SuperAdmin.findById(id);
      done(null, admin);
    } catch (err) {
      done(err, null);
    }
  });

  // Configure local strategy for Teacher
  passport.use(
    'teacher-local',
    new LocalStrategy(
      { usernameField: 'uname' }, // Specify the field used for authentication
      async (email, password, done) => {
        try {
          // Find the teacher by email
          const teacher = await Teacher.findOne({ email });
          if (!teacher) {
            return done(null, false, { message: 'Email not registered' });
          }

          // Match password
          const isMatch = await bcrypt.compare(password, teacher.password);
          if (!isMatch) {
            return done(null, false, { message: 'Incorrect password' });
          }

          // Success
          return done(null, teacher);
        } catch (err) {
          return done(err);
        }
      }
    )
  );

  // Serialize teacher to store in session
  passport.serializeUser((teacher, done) => {
    done(null, teacher.id);
  });

  // Deserialize teacher to retrieve from session
  passport.deserializeUser(async (id, done) => {
    try {
      const teacher = await Teacher.findById(id);
      done(null, teacher);
    } catch (err) {
      done(err, null);
    }
  });
};
