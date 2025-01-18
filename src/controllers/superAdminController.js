const SuperAdmin = require('../models/SuperAdmin');

exports.signup = async (req, res) => {
  try {
    const { firstName, lastName, username, email, password } = req.body;

    // Check if email or username is already taken
    const existingAdmin = await SuperAdmin.findOne({
      $or: [{ email }, { username }]
    });

    if (existingAdmin) {
      return res.status(400).send('Email or Username is already registered.');
    }

    // Create new SuperAdmin
    const superAdmin = new SuperAdmin({
      first_name: firstName,
      last_name: lastName,
      username,
      email,
      password
    });

    // Save to the database
    await superAdmin.save();

    // Redirect or send success response
    res.status(201).redirect('/adminlogin');
  } catch (error) {
    console.error('Error during signup:', error);
    res.status(500).send('Internal Server Error');
  }
};
