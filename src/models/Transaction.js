const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema(
  {
    // userId used for IDOR protection on every query
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'User ID is required'],
    },

    amount: {
      type: Number,
      required: [true, 'Amount is required'],
      min: [1, 'Amount must be at least 1'],
    },

    currency: {
      type: String,
      required: [true, 'Currency is required'],
      default: 'NPR',
      enum: {
        values: ['NPR', 'USD'],
        message: 'Invalid currency',
      },
    },

    paymentProvider: {
      type: String,
      default: 'stripe',
      enum: {
        values: ['stripe'],
        message: 'Invalid payment provider',
      },
    },

    // Esewa payment intent ID, NOT card details (PCI DSS)
    providerTransactionId: {
      type: String,
      default: null,
    },

    status: {
      type: String,
      required: [true, 'Status is required'],
      enum: {
        values: ['pending', 'completed', 'failed', 'cancelled'],
        message: 'Invalid transaction status',
      },
      default: 'pending',
    },

    description: {
      type: String,
      required: [true, 'Description is required'],
      trim: true,
      maxlength: [500, 'Description must not exceed 500 characters'],
    },

    //HMAC-SHA256 signature for transaction data integrity
    signature: {
      type: String,
      required: [true, 'Transaction signature is required'],
    },

    metadata: {
      appointmentId: { type: String, default: null },
      doctorName: { type: String, trim: true, maxlength: [100, 'Doctor name must not exceed 100 characters'] },
      serviceName: { type: String, trim: true, maxlength: [200, 'Service name must not exceed 200 characters'] },
    },
  },
  {
    timestamps: true,
  }
);

// Compound index on userId + createdAt for IDOR-protected queries
transactionSchema.index({ userId: 1, createdAt: -1 });
transactionSchema.index({ userId: 1, _id: 1 });
transactionSchema.index({ providerTransactionId: 1 });

module.exports = mongoose.model('Transaction', transactionSchema);