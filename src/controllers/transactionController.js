const Stripe = require('stripe');
const Transaction = require('../models/Transaction');
const { generateHMACSignature, verifyHMACSignature } = require('../utils/encryptionUtils');
const { logAction } = require('../middleware/loggingMiddleware');

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const createTransaction = async (req, res, next) => {
  try {
    const { amount, description } = req.body;
    const paymentIntent = await stripe.paymentIntents.create({
      amount: Math.round(amount * 100),
      currency: 'npr',
      description,
      automatic_payment_methods: { enabled: true }
    });

    const signature = generateHMACSignature(`${req.user.userId}:${amount}:${description}`);

    const transaction = await Transaction.create({
      userId: req.user.userId,
      amount,
      currency: 'NPR',
      paymentProvider: 'stripe',
      providerTransactionId: paymentIntent.id,
      status: 'pending',
      description,
      signature
    });

    await logAction('create_transaction')(req, res, () => {});
    res.status(201).json({ success: true, transaction, clientSecret: paymentIntent.client_secret });
  } catch (error) {
    next(error);
  }
};

const getTransactions = async (req, res, next) => {
  try {
    const transactions = await Transaction.find({ userId: req.user.userId }).sort({ createdAt: -1 });
    res.json({ success: true, transactions });
  } catch (error) {
    next(error);
  }
};

const verifySignature = (req, res) => {
  try {
    const { data, signature } = req.body;
    const valid = verifyHMACSignature(data, signature);
    res.json({ success: true, valid });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

const stripeWebhook = async (req, res, next) => {
  try {
    const event = req.body;
    if (event.type === 'payment_intent.succeeded') {
      await Transaction.updateOne(
        { providerTransactionId: event.data.object.id },
        { status: 'completed' }
      );
    }
    res.json({ received: true });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  createTransaction,
  getTransactions,
  verifySignature,
  stripeWebhook
};