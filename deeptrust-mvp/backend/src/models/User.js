const mongoose = require('mongoose');

const userSchema = new mongoose.Schema(
  {
    fullName: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
    role: {
      type: String,
      enum: ['investigator', 'administrator', 'institutional_user'],
      default: 'institutional_user',
    },
    isBlocked: { type: Boolean, default: false },
    lastLoginIp: String,
    lastDeviceFingerprint: String,
    lastLoginAt: Date,
  },
  { timestamps: true }
);

module.exports = mongoose.model('User', userSchema);
