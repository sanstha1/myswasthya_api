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

    // SECURITY: Argon2id hash, never plaintext. Null for OAuth users
    passwordHash: {
      type: String,
      default: null,
    },

    passwordHistory: {
      type: [String],
      default: [],
      validate: {
        validator: function (arr) { return arr.length <= 5; },
        message: 'Password history cannot exceed 5 entries',
      },
    },

    lastPasswordChange: { type: Date, default: Date.now },
    passwordExpiry: {
      type: Date,
      default: () => new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
    },

    // SECURITY: TOTP secret for RFC 6238 MFA
    totpSecret: { type: String, default: null },
    isMFAEnabled: { type: Boolean, default: false },
    backupCodes: { type: [String], default: [] },

    // SECURITY: Account lockout after 10 failed attempts (brute-force protection)
    failedLoginAttempts: { type: Number, default: 0, min: 0 },
    lockedUntil: { type: Date, default: null },

    // SECURITY: OAuth 2.0 provider fields
    oauthProvider: {
      type: String,
      enum: ['google', null],
      default: null,
    },
    oauthId: { type: String, default: null },

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

    isActive: { type: Boolean, default: true },
    lastLogin: { type: Date, default: null },
  },
  {
    timestamps: true,
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

userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ oauthId: 1 });
userSchema.index({ lockedUntil: 1 });
userSchema.index({ createdAt: 1 });

userSchema.methods.isLocked = function () {
  return this.lockedUntil && this.lockedUntil > Date.now();
};

userSchema.methods.isPasswordExpired = function () {
  return this.passwordExpiry && this.passwordExpiry < Date.now();
};

module.exports = mongoose.model('User', userSchema);