const mongoose = require("mongoose");

const failedLoginAttemptSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  attempts: {
    type: Number,
    default: 0
  },
  lockUntil: {
    type: Date
  }
});

module.exports = mongoose.model("FailedLoginAttempt", failedLoginAttemptSchema);