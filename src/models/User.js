const mongoose = require('mongoose');

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^\S+@\S+\.\S+$/, 'Invalid email format'],
      maxlength: [254, 'Email must not exceed 254 characters'],
    },

    // Password stored as Argon2id hash, never plaintext
    passwordHash: {
      type: String,
      required: [true, 'Password hash is required'],
    },

    // Password history - store last 5 hashes to prevent reuse
    passwordHistory: {
      type: [String],
      default: [],
      validate: {
        validator: function (arr) {
          return arr.length <= 5;
        },
        message: 'Password history cannot exceed 5 entries',
      },
    },

    // Password expiry enforced at 90 days (OWASP recommendation)
    lastPasswordChange: {
      type: Date,
      default: Date.now,
    },
    passwordExpiry: {
      type: Date,
      default: () => new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
    },

    // TOTP secret stored for MFA verification (RFC 6238)
    totpSecret: {
      type: String,
      default: null,
    },
    isMFAEnabled: {
      type: Boolean,
      default: false,
    },

    // Backup codes for MFA recovery, stored as hashes
    backupCodes: {
      type: [String],
      default: [],
    },

    // Account lockout after 5 failed attempts (brute-force protection)
    failedLoginAttempts: {
      type: Number,
      default: 0,
      min: 0,
    },
    lockedUntil: {
      type: Date,
      default: null,
    },

    // Session tracking for multi-device management
    activeSessions: {
      type: [
        {
          sessionId: String,
          userAgent: String,
          ipAddress: String,
          createdAt: { type: Date, default: Date.now },
          lastActive: { type: Date, default: Date.now },
        },
      ],
      default: [],
    },

    isActive: {
      type: Boolean,
      default: true,
    },
    lastLogin: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
    // Never return sensitive fields by default
    toJSON: {
      transform: function (doc, ret) {
        delete ret.passwordHash;
        delete ret.passwordHistory;
        delete ret.totpSecret;
        delete ret.backupCodes;
        delete ret.__v;
        return ret;
      },
    },
  }
);

// Index on email for fast lookup during authentication
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ lockedUntil: 1 });
userSchema.index({ createdAt: 1 });

// Check if account is currently locked
userSchema.methods.isLocked = function () {
  if (this.lockedUntil && this.lockedUntil > Date.now()) {
    return true;
  }
  return false;
};

// Check if password has expired (90 days)
userSchema.methods.isPasswordExpired = function () {
  return this.passwordExpiry && this.passwordExpiry < Date.now();
};

module.exports = mongoose.model('User', userSchema);