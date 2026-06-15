const Profile = require('../models/Profile');
const User = require('../models/User');
const MedicalRecord = require('../models/MedicalRecord');
const Transaction = require('../models/Transaction');
const AuditLog = require('../models/AuditLog');

const getProfile = async (req, res, next) => {
  try {
    const profile = await Profile.findOne({ userId: req.user.userId });
    if (!profile) return res.status(404).json({ success: false, error: 'Profile not found' });
    res.json({ success: true, profile });
  } catch (error) {
    next(error);
  }
};

const updateProfile = async (req, res, next) => {
  try {
    const profile = await Profile.findOneAndUpdate(
      { userId: req.user.userId },
      { $set: req.body },
      { new: true, upsert: true }
    );

    await AuditLog.create({
      userId: req.user.userId,
      action: 'update_profile',
      resource: 'profile',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] || ''
    });

    res.json({ success: true, profile });
  } catch (error) {
    next(error);
  }
};

const exportData = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.userId).select('-passwordHash -totpSecret -passwordHistory');
    const profile = await Profile.findOne({ userId: req.user.userId });
    const records = await MedicalRecord.find({ userId: req.user.userId });
    const transactions = await Transaction.find({ userId: req.user.userId });

    await AuditLog.create({
      userId: req.user.userId,
      action: 'export_data',
      resource: 'profile',
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] || ''
    });

    res.json({
      success: true,
      data: {
        user,
        profile,
        records,
        transactions
      }
    });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  getProfile,
  updateProfile,
  exportData
};