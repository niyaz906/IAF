const crypto = require('crypto');
const User = require('../Models/User');
const { generateToken } = require('../utils/jwt');

const OTP_EXPIRY_MINUTES = parseInt(process.env.OTP_EXPIRY_MINUTES || '5', 10);
const OTP_GATEWAY_URL =
  process.env.OTP_GATEWAY_URL || 'http://msg.com:8080/smsc/sends msg';

const buildOtpUrl = (to, otp) => {
  // Handle the space in the provided path by URL-encoding it
  const base = OTP_GATEWAY_URL.replace(' ', '%20');
  const url = new URL(base);
  url.searchParams.set('from', 'VAYUREADER');
  url.searchParams.set('to', to);
  url.searchParams.set('text', `Your OTP code for Login : ${otp} . Regards,`);
  return url.toString();
};

const sendOtpSms = async (to, otp) => {
  const devMode = process.env.SKIP_OTP_SEND === 'true';
  // In dev/test you can skip the real SMS send by setting SKIP_OTP_SEND=true
  if (devMode) {
    console.log(`[DEV] OTP to ${to}: ${otp}`);
    return { devMode: true };
  }

  const url = buildOtpUrl(to, otp);
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`OTP gateway error: ${response.status} ${response.statusText}`);
  }
  return { devMode: false };
};

const signup = async (req, res) => {
  try {
    const { name, officer_id, phone_number, password } = req.body;

    
    const existingUser = await User.findOne({
      $or: [{ phone_number }, { officer_id }]
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User with this phone number or officer ID already exists'
      });
    }

    const user = new User({ name, officer_id, phone_number, password });
    await user.save();

    const token = generateToken(user._id);

    res.status(201).json({
      success: true,
      message: 'User created successfully',
      token,
      user: {
        id: user._id,
        name: user.name,
        officer_id: user.officer_id,
        phone_number: user.phone_number
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: error.message
    });
  }
};

const login = async (req, res) => {
  try {
    const { phone_number, password } = req.body;

    // Find user by phone number
    const user = await User.findOne({ phone_number });
    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    
    const token = generateToken(user._id);

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        officer_id: user.officer_id,
        phone_number: user.phone_number
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: error.message
    });
  }
};

const getProfile = async (req, res) => {
  res.json({
    success: true,
    user: req.user
  });
};

module.exports = { signup, login, getProfile };

// OTP-based request for both login and signup flows
const requestOtp = async (req, res) => {
  try {
    const { phone_number, name, officer_id } = req.body;

    let user = await User.findOne({ phone_number });

    if (!user && (!name || !officer_id)) {
      return res.status(400).json({
        success: false,
        message: 'New users must provide name and officer_id to receive OTP'
      });
    }

    if (!user) {
      const officerExists = await User.findOne({ officer_id });
      if (officerExists) {
        return res.status(400).json({
          success: false,
          message: 'Officer ID already registered'
        });
      }
      user = new User({ name, officer_id, phone_number });
    }

    const otp = crypto.randomInt(100000, 999999).toString();
    user.otpCode = otp;
    user.otpExpiresAt = new Date(Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000);
    await user.save();

    let sendResult;
    try {
      sendResult = await sendOtpSms(phone_number, otp);
    } catch (smsError) {
      return res.status(502).json({
        success: false,
        message: 'Failed to send OTP',
        error: smsError.message
      });
    }

    const devMode = sendResult?.devMode === true;
    res.json({
      success: true,
      message: devMode ? 'OTP generated (DEV MODE - SMS skipped)' : 'OTP sent successfully',
      ...(devMode ? { otp } : {}) // return OTP only in explicit dev mode for local testing
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: error.message
    });
  }
};

const verifyOtp = async (req, res) => {
  try {
    const { phone_number, otp } = req.body;

    const user = await User.findOne({ phone_number });
    if (!user || !user.otpCode || !user.otpExpiresAt) {
      return res.status(400).json({
        success: false,
        message: 'No active OTP for this number'
      });
    }

    const now = new Date();
    if (now > user.otpExpiresAt) {
      return res.status(400).json({
        success: false,
        message: 'OTP has expired'
      });
    }

    if (user.otpCode !== otp) {
      return res.status(400).json({
        success: false,
        message: 'Invalid OTP'
      });
    }

    user.otpCode = undefined;
    user.otpExpiresAt = undefined;
    await user.save();

    const token = generateToken(user._id);
    res.json({
      success: true,
      message: 'OTP verified successfully',
      token,
      user: {
        id: user._id,
        name: user.name,
        officer_id: user.officer_id,
        phone_number: user.phone_number
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Server error',
      error: error.message
    });
  }
};


module.exports = { signup, login, getProfile, requestOtp, verifyOtp };
