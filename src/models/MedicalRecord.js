const mongoose = require('mongoose');

const medicalRecordSchema = new mongoose.Schema(
  {
    // userId used for IDOR protection on every query
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'User ID is required'],
    },

    title: {
      type: String,
      required: [true, 'Record title is required'],
      trim: true,
      maxlength: [200, 'Title must not exceed 200 characters'],
    },

    recordType: {
      type: String,
      required: [true, 'Record type is required'],
      enum: {
        values: ['lab_report', 'prescription', 'scan', 'discharge_summary', 'vaccination', 'other'],
        message: 'Invalid record type',
      },
    },

    // File path encrypted with AES-256-GCM before storage
    filePath: {
      type: String,
      required: [true, 'File path is required'],
    },

    fileSize: {
      type: Number,
      required: [true, 'File size is required'],
      min: [0, 'File size cannot be negative'],
      max: [10485760, 'File size cannot exceed 10MB'],
    },

    mimeType: {
      type: String,
      required: [true, 'MIME type is required'],
      // SECURITY: Only allow PDF and images
      enum: {
        values: ['application/pdf', 'image/png', 'image/jpeg'],
        message: 'Invalid file type - only PDF, PNG, JPEG allowed',
      },
    },

    // SHA-256 hash for file integrity verification
    fileHash: {
      type: String,
      required: [true, 'File hash is required'],
    },

    // Flag indicating filePath is AES-256-GCM encrypted
    isEncrypted: {
      type: Boolean,
      default: true,
    },

    uploadedAt: {
      type: Date,
      default: Date.now,
    },

    metadata: {
      originalName: {
        type: String,
        trim: true,
        maxlength: [255, 'Original filename must not exceed 255 characters'],
      },
      description: {
        type: String,
        trim: true,
        maxlength: [500, 'Description must not exceed 500 characters'],
      },
      doctorName: {
        type: String,
        trim: true,
        maxlength: [100, 'Doctor name must not exceed 100 characters'],
      },
      recordDate: {
        type: Date,
      },
    },
  },
  {
    timestamps: true,
  }
);

// Compound index on userId + uploadedAt for IDOR-protected queries
medicalRecordSchema.index({ userId: 1, uploadedAt: -1 });
medicalRecordSchema.index({ userId: 1, _id: 1 });

module.exports = mongoose.model('MedicalRecord', medicalRecordSchema);