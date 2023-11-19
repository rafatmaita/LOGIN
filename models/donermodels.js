const mongoose = require('mongoose');

// Donor Schema
const donorSchema = new mongoose.Schema({
  userName: { type: String, required: true },
  emailAddress: { type: String, required: true, unique: true },
  password: { type: String},
  googleID : String,
});

// Donation Schema
const donationSchema = new mongoose.Schema({
  amountDonated: { type: Number, required: true },
  donorId: { type: mongoose.Schema.Types.ObjectId, ref: 'Donor', required: true },
});

// User Schema
const userSchema = new mongoose.Schema({
    type: { type: String, enum: ['School', 'University', 'Institution', 'Park'], required: true },
    username: { type: String, required: true },
    emailAddress: { type: String, required: true, unique: true },
    password: { type: String, required: true },

  });
  
  // Request Schema
  const requestSchema = new mongoose.Schema({

    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    address: { type: String, required: true },
    description: { type: String },
    dueDate: { type: Date, required: true },
});

// Create mongoose models
const Donor = mongoose.model('Donor', donorSchema);
const Donation = mongoose.model('Donation', donationSchema);
const User = mongoose.model('User', userSchema);
const Request = mongoose.model('Request', requestSchema);

module.exports = { Donor, Donation, User,Request  };