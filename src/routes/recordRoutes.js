const express = require('express');
const router = express.Router();
const { uploadRecord, getRecords, downloadRecord, deleteRecord } = require('../controllers/recordController');
const { authenticate } = require('../middleware/authMiddleware');
const { protectResource, validateObjectId } = require('../middleware/rbacMiddleware');

// All record routes require authentication AND IDOR protection
router.post('/upload', authenticate, protectResource, uploadRecord);
router.get('/', authenticate, protectResource, getRecords);
router.get('/:id/download', authenticate, protectResource, validateObjectId('id'), downloadRecord);
router.delete('/:id', authenticate, protectResource, validateObjectId('id'), deleteRecord);

module.exports = router;