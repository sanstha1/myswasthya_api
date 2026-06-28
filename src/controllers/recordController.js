const fs = require('fs');
const path = require('path');
const MedicalRecord = require('../models/MedicalRecord');
const { generateFileHash, validateFileType, validateFileSize } = require('../utils/fileUtils');
const { encrypt, decrypt } = require('../utils/encryptionUtils');
const { logAction } = require('../middleware/loggingMiddleware');

const uploadRecord = async (req, res, next) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, error: 'File is required' });
    if (!validateFileType(req.file.mimetype)) return res.status(400).json({ success: false, error: 'Invalid file type' });
    if (!validateFileSize(req.file.size)) return res.status(400).json({ success: false, error: 'File too large' });

    const fileHash = generateFileHash(req.file.buffer);
    const encryptedPath = encrypt(req.file.path);

    const record = await MedicalRecord.create({
      userId: req.user.userId,
      title: req.body.title,
      recordType: req.body.recordType,
      filePath: encryptedPath,
      fileSize: req.file.size,
      fileHash,
      metadata: req.body.metadata || {}
    });

    await logAction('upload_record')(req, res, () => {});
    res.status(201).json({ success: true, record });
  } catch (error) {
    next(error);
  }
};

const getRecords = async (req, res, next) => {
  try {
    const records = await MedicalRecord.find({ userId: req.user.userId }).sort({ uploadedAt: -1 });
    res.json({ success: true, records });
  } catch (error) {
    next(error);
  }
};

const downloadRecord = async (req, res, next) => {
  try {
    const record = await MedicalRecord.findOne({ _id: req.params.id, userId: req.user.userId });
    if (!record) return res.status(404).json({ success: false, error: 'Record not found' });

    const filePath = decrypt(record.filePath);
    if (!fs.existsSync(filePath)) return res.status(404).json({ success: false, error: 'File not found' });

    await logAction('download_record')(req, res, () => {});
    res.download(filePath);
  } catch (error) {
    next(error);
  }
};

const deleteRecord = async (req, res, next) => {
  try {
    const record = await MedicalRecord.findOne({ _id: req.params.id, userId: req.user.userId });
    if (!record) return res.status(404).json({ success: false, error: 'Record not found' });

    const filePath = decrypt(record.filePath);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    await record.deleteOne();

    await logAction('delete_record')(req, res, () => {});
    res.json({ success: true, message: 'Record deleted' });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  uploadRecord,
  getRecords,
  downloadRecord,
  deleteRecord
};