const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema(
  {
    // Audit log linked to user for accountability
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      default: null,
    },

    // Action enum prevents arbitrary strings in audit trail
    action: {
      type: String,
      required: [true, 'Action is required'],
      enum: {
        values: [
          'register',
          'login',
          'login_failed',
          'logout',
          'update_profile',
          'export_data',
          'upload_record',
          'download_record',
          'delete_record',
          'create_transaction',
          'complete_transaction',
          'change_password',
          'enable_mfa',
          'disable_mfa',
          'account_locked',
          'password_expired',
          'session_invalidated',
        ],
        message: 'Invalid action type',
      },
    },

    resource: {
      type: String,
      default: null,
      maxlength: [200, 'Resource path must not exceed 200 characters'],
    },

    // IP address logged for forensic analysis
    ipAddress: {
      type: String,
      default: null,
      maxlength: [45, 'IP address must not exceed 45 characters'],
    },

    userAgent: {
      type: String,
      default: null,
      maxlength: [500, 'User agent must not exceed 500 characters'],
    },

    // Extra context stored without sensitive data
    details: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },

    timestamp: {
      type: Date,
      default: Date.now,
    },
  },
  {
    // Disable updates - audit logs are immutable (append-only)
    strict: true,
  }
);

//Index for fast forensic queries by user and time
auditLogSchema.index({ userId: 1, timestamp: -1 });
auditLogSchema.index({ action: 1, timestamp: -1 });
auditLogSchema.index({ ipAddress: 1, timestamp: -1 });
auditLogSchema.index({ timestamp: -1 });

//Prevent any updates to audit logs (immutable records)
auditLogSchema.pre('findOneAndUpdate', function () {
  throw new Error('Audit logs are immutable and cannot be updated');
});
auditLogSchema.pre('updateOne', function () {
  throw new Error('Audit logs are immutable and cannot be updated');
});
auditLogSchema.pre('updateMany', function () {
  throw new Error('Audit logs are immutable and cannot be updated');
});

module.exports = mongoose.model('AuditLog', auditLogSchema);