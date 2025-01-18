const mongoose = require('mongoose');
require('dotenv').config();

const connectDB = async () => {
  console.log('MONGO_URI:', process.env.MONGODB_URI); // Debug: Check if the URI is correctly loaded

  try {
    await mongoose.connect(process.env.MONGODB_URI); // Ensure this matches the key in your .env file
    console.log('MongoDB connected successfully!');
  } catch (err) {
    console.error('MongoDB connection error:', err.message);
    process.exit(1); // Exit with failure
  }
};

module.exports = connectDB;
