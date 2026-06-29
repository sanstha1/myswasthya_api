const path = require('path');
const fs = require('fs');
const multer = require('multer');
const MedicalRecord = require('../models/MedicalRecord');
const { generateFileHash, validateFileType, validateFileSize, deleteFile } = require('../utils/fileUtils');
const { encrypt, decrypt } = require('../utils/encryptionUtils');
const { logAction } = require('../middleware/loggingMiddleware');
const { z } = require('zod');
const escapeHtml = require('escape-html');

const UPLOAD_DIR = path.join(__dirname, '../../uploads');
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// Multer storage with random filename
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${Math.random().toString(36).slice(2)}${path.extname(file.originalname).toLowerCase()}`;
    cb(null, uniqueName);
  },
});

// File type filter
const fileFilter = (req, file, cb) => {
  const validation = validateFileType(file.mimetype, file.originalname);
  if (!validation.valid) cb(new Error(validation.error), false);
  else cb(null, true);
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 10 * 1024 * 1024, files: 1 },
});

const uploadMiddleware = upload.single('file');

/**
 * POST /api/records/upload
 * File validation, SHA-256 integrity hash, AES-256-GCM path encryption
 */
async function uploadRecord(req, res) {
  uploadMiddleware(req, res, async (err) => {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ success: false, message: 'File size exceeds 10MB limit' });
      }
      return res.status(400).json({ success: false, message: err.message || 'File upload failed' });
    }

    try {
      if (!req.file) return res.status(400).json({ success: false, message: 'No file uploaded' });

      const { userId } = req.user;
      const filePath = req.file.path;

      const sizeValidation = validateFileSize(req.file.size);
      if (!sizeValidation.valid) {
        await deleteFile(filePath);
        return res.status(400).json({ success: false, message: sizeValidation.error });
      }

      const metaSchema = z.object({
        title: z.string().min(1).max(200).trim(),
        recordType: z.enum(['lab_report', 'prescription', 'scan', 'discharge_summary', 'vaccination', 'other']),
        description: z.string().max(500).optional().default(''),
        doctorName: z.string().max(100).optional().default(''),
        recordDate: z.string().optional(),
      });

      const metaParse = metaSchema.safeParse(req.body);
      if (!metaParse.success) {
        await deleteFile(filePath);
        return res.status(400).json({
          success: false,
          message: 'Invalid record metadata',
          errors: metaParse.error.errors.map((e) => e.message),
        });
      }

      const meta = metaParse.data;
      const fileHash = await generateFileHash(filePath);
      const encryptedPath = encrypt(filePath);

      const record = await MedicalRecord.create({
        userId,
        title: escapeHtml(meta.title),
        recordType: meta.recordType,
        filePath: encryptedPath,
        fileSize: req.file.size,
        mimeType: req.file.mimetype,
        fileHash,
        isEncrypted: true,
        uploadedAt: new Date(),
        metadata: {
          originalName: escapeHtml(req.file.originalname),
          description: escapeHtml(meta.description),
          doctorName: escapeHtml(meta.doctorName),
          recordDate: meta.recordDate ? new Date(meta.recordDate) : undefined,
        },
      });

      await logAction(userId, 'upload_record', req, {
        recordId: record._id.toString(),
        fileSize: req.file.size,
        recordType: meta.recordType,
      });

      return res.status(201).json({
        success: true,
        message: 'Medical record uploaded successfully',
        data: {
          _id: record._id,
          title: record.title,
          recordType: record.recordType,
          fileSize: record.fileSize,
          mimeType: record.mimeType,
          uploadedAt: record.uploadedAt,
          metadata: record.metadata,
        },
      });

    } catch (err) {
      if (req.file?.path) await deleteFile(req.file.path);
      console.error('[RECORDS] Upload error:', err.message);
      return res.status(500).json({ success: false, message: 'Record upload failed' });
    }
  });
}

/**
 * GET /api/records
 * IDOR protected - only returns records belonging to authenticated userId
 */
async function getRecords(req, res) {
  try {
    const { userId } = req.user;
    const records = await MedicalRecord.find({ userId })
      .select('-filePath')
      .sort({ uploadedAt: -1 })
      .limit(50);

    return res.status(200).json({ success: true, data: records });
  } catch (err) {
    console.error('[RECORDS] Get records error:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to retrieve records' });
  }
}

/**
 * GET /api/records/:id/download
 * IDOR protection, decrypts file path, verifies integrity hash
 */
async function downloadRecord(req, res) {
  try {
    const { userId } = req.user;
    const { id } = req.params;

    const record = await MedicalRecord.findOne({ _id: id, userId });
    if (!record) return res.status(404).json({ success: false, message: 'Record not found' });

    let filePath;
    try {
      filePath = decrypt(record.filePath);
    } catch {
      return res.status(500).json({ success: false, message: 'File access error' });
    }

    if (!fs.existsSync(filePath)) return res.status(404).json({ success: false, message: 'File not found on server' });

    const { verifyFileIntegrity } = require('../utils/fileUtils');
    const isIntact = await verifyFileIntegrity(filePath, record.fileHash);
    if (!isIntact) {
      console.error(`[SECURITY ALERT] File integrity check FAILED for record ${id}`);
      return res.status(500).json({ success: false, message: 'File integrity verification failed' });
    }

    await logAction(userId, 'download_record', req, { recordId: id });

    res.setHeader('Content-Type', record.mimeType);
    res.setHeader('Content-Disposition', `attachment; filename="${record.metadata?.originalName || 'record'}"`);
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.setHeader('Pragma', 'no-cache');

    return res.sendFile(filePath);
  } catch (err) {
    console.error('[RECORDS] Download error:', err.message);
    return res.status(500).json({ success: false, message: 'File download failed' });
  }
}

/**
 * DELETE /api/records/:id
 * IDOR protection - verifies record belongs to authenticated user before deletion
 */
async function deleteRecord(req, res) {
  try {
    const { userId } = req.user;
    const { id } = req.params;

    const record = await MedicalRecord.findOne({ _id: id, userId });
    if (!record) return res.status(404).json({ success: false, message: 'Record not found' });

    let filePath;
    try {
      filePath = decrypt(record.filePath);
    } catch {
      filePath = null;
    }

    await MedicalRecord.findByIdAndDelete(id);
    if (filePath) await deleteFile(filePath);

    await logAction(userId, 'delete_record', req, { recordId: id });

    return res.status(200).json({ success: true, message: 'Record deleted successfully' });
  } catch (err) {
    console.error('[RECORDS] Delete error:', err.message);
    return res.status(500).json({ success: false, message: 'Record deletion failed' });
  }
}

module.exports = { uploadRecord, getRecords, downloadRecord, deleteRecord };
