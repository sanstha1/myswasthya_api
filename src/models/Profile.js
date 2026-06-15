const mongoose = require('mongoose');

const profileSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true
  },
  fullName: {
    type: String,
    trim: true
  },
  phone: {
    type: String,
    trim: true
  },
  dateOfBirth: {
    type: Date
  },
  bloodGroup: {
    type: String,
    enum: ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-']
  },
  photoUrl: {
    type: String
  },
  allergies: {
    type: String
  },
  emergencyContact: {
    type: String
  },
  medicalHistory: {
    type: String
  },
  address: {
    type: String
  }
});

profileSchema.index({ userId: 1 });

module.exports = mongoose.model('Profile', profileSchema);