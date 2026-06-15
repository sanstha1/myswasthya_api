const express = require('express');
const { authenticate } = require('../middleware/authMiddleware');
const { createTransaction, getTransactions, verifySignature, stripeWebhook } = require('../controllers/transactionController');

const router = express.Router();

router.post('/create', authenticate, createTransaction);
router.get('/', authenticate, getTransactions);
router.post('/verify-signature', authenticate, verifySignature);
router.post('/webhook', express.raw({ type: 'application/json' }), stripeWebhook);

module.exports = router;