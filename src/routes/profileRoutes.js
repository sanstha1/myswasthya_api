const express = require('express');
const router = express.Router();
const { getProfile, updateProfile, exportData } = require('../controllers/profileController');
const { authenticate } = require('../middleware/authMiddleware');
const { protectResource } = require('../middleware/rbacMiddleware');

// All profile routes require authentication AND IDOR protection
router.get('/', authenticate, protectResource, getProfile);
router.put('/', authenticate, protectResource, updateProfile);
router.get('/export', authenticate, protectResource, exportData);

module.exports = router;