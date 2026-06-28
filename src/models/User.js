const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  passwordHash: {
    type: String,
    required: true
  },
  totpSecret: {
    type: String,
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastPasswordChange: {
    type: Date,
    default: Date.now
  },
  passwordExpiry: {
    type: Date,
    required: true
  },
  failedLoginAttempts: {
    type: Number,
    default: 0
  },
  lockedUntil: {
    type: Date
  },
  isActive: {
    type: Boolean,
    default: true
  },
  lastLogin: {
    type: Date
  },
  passwordHistory: {
    type: [String],
    default: []
  }
});

userSchema.index({ email: 1 });

module.exports = mongoose.model('User', userSchema);