const mongoose = require('mongoose');

const medicalRecordSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  title: {
    type: String,
    required: true,
    trim: true
  },
  recordType: {
    type: String,
    required: true,
    enum: ['blood_test', 'xray', 'prescription', 'lab_report', 'ultrasound', 'other']
  },
  filePath: {
    type: String,
    required: true
  },
  fileSize: {
    type: Number
  },
  fileHash: {
    type: String,
    required: true
  },
  uploadedAt: {
    type: Date,
    default: Date.now
  },
  isEncrypted: {
    type: Boolean,
    default: true
  },
  metadata: {
    type: Object
  }
});

medicalRecordSchema.index({ userId: 1 });
medicalRecordSchema.index({ uploadedAt: -1 });

module.exports = mongoose.model('MedicalRecord', medicalRecordSchema);