const express = require('express');
const multer = require('multer');
const { authenticate } = require('../middleware/authMiddleware');
const { uploadRecord, getRecords, downloadRecord, deleteRecord } = require('../controllers/recordController');

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

router.post('/upload', authenticate, upload.single('file'), uploadRecord);
router.get('/', authenticate, getRecords);
router.get('/:id/download', authenticate, downloadRecord);
router.delete('/:id', authenticate, deleteRecord);

module.exports = router;