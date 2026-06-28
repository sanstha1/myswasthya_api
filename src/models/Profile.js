const mongoose = require('mongoose');

const profileSchema = new mongoose.Schema(
  {
    // userId links profile to user, used for IDOR protection
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'User ID is required'],
      unique: true,
    },

    fullName: {
      type: String,
      required: [true, 'Full name is required'],
      trim: true,
      maxlength: [100, 'Full name must not exceed 100 characters'],
    },

    phone: {
      type: String,
      trim: true,
      match: [/^[+]?[\d\s\-()]{7,20}$/, 'Invalid phone number format'],
      maxlength: [20, 'Phone number must not exceed 20 characters'],
    },

    dateOfBirth: {
      type: Date,
    },

    bloodGroup: {
      type: String,
      enum: {
        values: ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-', 'Unknown'],
        message: 'Invalid blood group',
      },
      default: 'Unknown',
    },

    // File path stored, actual file validated on upload
    photoUrl: {
      type: String,
      default: null,
      maxlength: [500, 'Photo URL must not exceed 500 characters'],
    },

    // Input sanitized before storage to prevent XSS
    allergies: {
      type: String,
      default: '',
      maxlength: [1000, 'Allergies text must not exceed 1000 characters'],
    },

    emergencyContact: {
      name: {
        type: String,
        trim: true,
        maxlength: [100, 'Emergency contact name must not exceed 100 characters'],
      },
      phone: {
        type: String,
        trim: true,
        maxlength: [20, 'Emergency contact phone must not exceed 20 characters'],
      },
      relationship: {
        type: String,
        trim: true,
        maxlength: [50, 'Relationship must not exceed 50 characters'],
      },
    },

    // Input sanitized before storage to prevent XSS
    medicalHistory: {
      type: String,
      default: '',
      maxlength: [5000, 'Medical history must not exceed 5000 characters'],
    },

    address: {
      street: { type: String, trim: true, maxlength: [200, 'Street must not exceed 200 characters'] },
      city: { type: String, trim: true, maxlength: [100, 'City must not exceed 100 characters'] },
      district: { type: String, trim: true, maxlength: [100, 'District must not exceed 100 characters'] },
      province: { type: String, trim: true, maxlength: [100, 'Province must not exceed 100 characters'] },
      postalCode: { type: String, trim: true, maxlength: [20, 'Postal code must not exceed 20 characters'] },
    },
  },
  {
    timestamps: true,
  }
);

// Index on userId for fast IDOR checks
profileSchema.index({ userId: 1 }, { unique: true });

module.exports = mongoose.model('Profile', profileSchema);