const Profile = require('../models/Profile');
const User = require('../models/User');
const MedicalRecord = require('../models/MedicalRecord');
const { logAction } = require('../middleware/loggingMiddleware');
const { z } = require('zod');
const escapeHtml = require('escape-html');

// Zod schema for profile update validation
const profileUpdateSchema = z.object({
  fullName: z.string().min(2).max(100).trim().optional(),
  phone: z.string().max(20).regex(/^[+]?[\d\s\-()]{7,20}$/, 'Invalid phone format').optional().or(z.literal('')),
  dateOfBirth: z.string().optional().or(z.literal('')),
  bloodGroup: z.enum(['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-', 'Unknown']).optional(),
  allergies: z.string().max(1000).optional(),
  medicalHistory: z.string().max(5000).optional(),
  emergencyContact: z.object({
    name: z.string().max(100).optional(),
    phone: z.string().max(20).optional(),
    relationship: z.string().max(50).optional(),
  }).optional(),
  address: z.object({
    street: z.string().max(200).optional(),
    city: z.string().max(100).optional(),
    district: z.string().max(100).optional(),
    province: z.string().max(100).optional(),
    postalCode: z.string().max(20).optional(),
  }).optional(),
});

/**
 * GET /api/profile
 * IDOR protection - only returns profile belonging to authenticated userId
 */
async function getProfile(req, res) {
  try {
    const { userId } = req.user;
    const profile = await Profile.findOne({ userId });

    if (!profile) {
      return res.status(404).json({ success: false, message: 'Profile not found' });
    }

    return res.status(200).json({ success: true, data: profile });

  } catch (err) {
    console.error('[PROFILE] Get profile error:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to retrieve profile' });
  }
}

/**
 * PUT /api/profile
 * IDOR protection, input sanitization, Zod validation
 */
async function updateProfile(req, res) {
  try {
    const { userId } = req.user;

    const parseResult = profileUpdateSchema.safeParse(req.body);
    if (!parseResult.success) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: parseResult.error.errors.map((e) => e.message),
      });
    }

    const data = parseResult.data;
    const sanitizedUpdate = {};

    if (data.fullName !== undefined) sanitizedUpdate.fullName = escapeHtml(data.fullName.trim());
    if (data.phone !== undefined) sanitizedUpdate.phone = data.phone.trim();
    if (data.dateOfBirth !== undefined && data.dateOfBirth) {
      const dob = new Date(data.dateOfBirth);
      if (isNaN(dob.getTime())) {
        return res.status(400).json({ success: false, message: 'Invalid date of birth' });
      }
      sanitizedUpdate.dateOfBirth = dob;
    }
    if (data.bloodGroup !== undefined) sanitizedUpdate.bloodGroup = data.bloodGroup;
    if (data.allergies !== undefined) sanitizedUpdate.allergies = escapeHtml(data.allergies.trim());
    if (data.medicalHistory !== undefined) sanitizedUpdate.medicalHistory = escapeHtml(data.medicalHistory.trim());

    if (data.emergencyContact) {
      sanitizedUpdate.emergencyContact = {
        name: data.emergencyContact.name ? escapeHtml(data.emergencyContact.name.trim()) : undefined,
        phone: data.emergencyContact.phone?.trim(),
        relationship: data.emergencyContact.relationship ? escapeHtml(data.emergencyContact.relationship.trim()) : undefined,
      };
    }

    if (data.address) {
      sanitizedUpdate.address = {
        street: data.address.street ? escapeHtml(data.address.street.trim()) : undefined,
        city: data.address.city ? escapeHtml(data.address.city.trim()) : undefined,
        district: data.address.district ? escapeHtml(data.address.district.trim()) : undefined,
        province: data.address.province ? escapeHtml(data.address.province.trim()) : undefined,
        postalCode: data.address.postalCode?.trim(),
      };
    }

    const profile = await Profile.findOneAndUpdate(
      { userId },
      { $set: sanitizedUpdate },
      { new: true, runValidators: true }
    );

    if (!profile) {
      return res.status(404).json({ success: false, message: 'Profile not found' });
    }

    await logAction(userId, 'update_profile', req);

    return res.status(200).json({
      success: true,
      message: 'Profile updated successfully',
      data: profile,
    });

  } catch (err) {
    console.error('[PROFILE] Update profile error:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to update profile' });
  }
}

/**
 * GET /api/profile/export
 * GDPR-compliant data export - only exports authenticated user's own data
 */
async function exportData(req, res) {
  try {
    const { userId } = req.user;

    const [user, profile, records] = await Promise.all([
      User.findById(userId).select('email createdAt lastLogin isActive'),
      Profile.findOne({ userId }),
      MedicalRecord.find({ userId }).select('-filePath'),
    ]);

    const exportData = {
      exportedAt: new Date().toISOString(),
      user: user || {},
      profile: profile || {},
      medicalRecords: records || [],
    };

    await logAction(userId, 'export_data', req);

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="myswasthya-export.json"');
    return res.status(200).json({ success: true, data: exportData });

  } catch (err) {
    console.error('[PROFILE] Export data error:', err.message);
    return res.status(500).json({ success: false, message: 'Data export failed' });
  }
}

module.exports = { getProfile, updateProfile, exportData };