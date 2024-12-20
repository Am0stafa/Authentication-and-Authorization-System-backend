import mongoose, { Document, Schema } from 'mongoose';
import bcrypt from 'bcrypt';

export interface IUser extends Document {
  email: string;
  firstName: string;
  lastName: string;
  password: string;
  lastLogin: Date;
  isVerified: boolean;
  verificationToken: string;
  verificationTokenExpires: Date;
  resetPasswordToken: string;
  resetPasswordExpires: Date;
  createdAt: Date;
  updatedAt: Date;
  comparePassword(candidatePassword: string): Promise<boolean>;
  refreshTokens: Array<{
    token: string;
    family: string;
    version: number;
    expiresAt: Date;
    issuedAt: Date;
    lastUsed: Date;
    issuedBy: string;
    device: string;
    isRevoked: boolean;
  }>;
}

const userSchema = new Schema<IUser>({
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    maxlength: 255
  },
  firstName: {
    type: String,
    required: true,
    trim: true,
    maxlength: 255
  },
  lastName: {
    type: String,
    required: true,
    trim: true,
    maxlength: 255
  },
  password: {
    type: String,
    required: true,
    minlength: 6,
    maxlength: 1024,
    select: false
  },
  lastLogin: {
    type: Date,
    default: null,
    select: false
  },
  isVerified: {
    type: Boolean,
    default: false,
    select: false
  },
  verificationToken: {
    type: String,
    default: null,
    select: false
  },
  verificationTokenExpires: {
    type: Date,
    default: null,
    select: false
  },
  resetPasswordToken: {
    type: String,
    default: null,
    select: false
  },
  resetPasswordExpires: {
    type: Date,
    default: null,
    select: false
  },
  refreshTokens: [{
    token: {
      type: String,
      required: true,
      select: false
    },
    family: {
      type: String,
      required: true
    },
    version: {
      type: Number,
      required: true
    },
    expiresAt: {
      type: Date,
      required: true
    },
    issuedAt: {
      type: Date,
      required: true
    },
    lastUsed: {
      type: Date,
      required: true
    },
    issuedBy: {
      type: String,
      required: true
    },
    device: {
      type: String,
      required: true
    },
    isRevoked: {
      type: Boolean,
      default: false
    }
  }]
}, {
  timestamps: true
});

// Hash password before saving
userSchema.pre('save', async function(this: IUser, next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error as Error);
  }
});

// Method to compare password for login
userSchema.methods.comparePassword = async function(candidatePassword: string): Promise<boolean> {
  try {
    return await bcrypt.compare(candidatePassword, this.password);
  } catch (error) {
    throw error;
  }
};

// Create indexes
userSchema.index({ email: 1 });
userSchema.index({ 
  email: 1, 
  isVerified: 1, 
  verificationTokenExpires: 1 
});
userSchema.index({ resetPasswordToken: 1 });

export const User = mongoose.model<IUser>('User', userSchema);
