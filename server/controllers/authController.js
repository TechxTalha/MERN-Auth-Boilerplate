const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const {
  sendVerifySuccessEmail,
  sendPasswordResetEmail,
  sendResetSuccessEmail,
  sendVerificationEmail,
} = require("../services/emailServices");

const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: "24h",
  });
};

// Register Admin Controller (use with caution)
const registerAdmin = asyncHandler(async (req, res) => {
  const { name, email, password, phoneno } = req.body;

  const adminExists = await User.findOne({ email });
  if (adminExists) {
    return res.status(400).json({ message: "Email already in use" });
  }

  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);

  const admin = await User.create({
    name,
    email,
    password: hashedPassword,
    phoneno,
    status: "verified",
    type: "admin",
  });

  if (admin) {
    res.status(201).json({
      message: "Admin registered successfully",
      admin: {
        id: admin._id,
        name: admin.name,
        email: admin.email,
        type: admin.type,
        phoneno: admin.phoneno,
        status: admin.status,
      },
    });
  } else {
    res.status(400).json({ message: "Invalid admin data" });
  }
});

// Register Controller
const registerUser = asyncHandler(async (req, res) => {
  const { name, email, password, phoneno } = req.body;

  const userExists = await User.findOne({ email });
  if (userExists)
    return res.status(400).json({ message: "Email already in use" });

  const phoneExists = await User.findOne({ phoneno });
  if (phoneExists)
    return res.status(400).json({ message: "Phone number already in use" });

  const user = await User.create({
    name,
    email,
    password,
    phoneno,
    status: "unverified",
    type: "user",
  });

  await sendVerificationEmail(user);

  res.status(201).json({
    message: "User registered. Please check your email to verify your account.",
  });
});

//verify email controller
const verifyEmail = asyncHandler(async (req, res) => {
  const { token } = req.query;

  if (!token)
    return res.status(400).json({ message: "Verification token is missing." });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) return res.status(404).json({ message: "User not found." });
    if (user.status === "verified")
      return res.status(400).json({ message: "User already verified." });

    user.status = "verified";
    await user.save();

    await sendVerifySuccessEmail(user);

    res.status(200).json({ message: "Email verified successfully." });
  } catch (err) {
    res.status(400).json({ message: "Invalid or used token." });
  }
});

// Login Controller
const login = asyncHandler(async (req, res) => {
  const { email, password } = req.body;

  // Find the user by email
  const user = await User.findOne({ email });

  if (!user) {
    return res.status(400).json({ message: "Invalid email or password" });
  }

  // Check if user is verified
  if (user.status !== "verified") {
    return res.status(400).json({ message: "Email not verified" });
  }

  // Check if password matches
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).json({ message: "Invalid email or password" });
  }

  // Generate JWT token
  const token = generateToken(user._id);

  // Set cookie with token
  res.cookie("token", token, {
    path: "/",
    httpOnly: true,
    expires:
      user.type === "user"
        ? new Date(Date.now() + 1000 * 86400) // 24 hours
        : new Date(Date.now() + 1000 * 7200), // 2 hours
    sameSite: "none",
    secure: true,
  });

  // Return user data without password
  return res.status(200).json({
    message: "Login successful",
    user: {
      id: user._id,
      name: user.name,
      email: user.email,
      type: user.type,
      phoneno: user.phoneno,
    },
    token,
  });
});

// Middleware to check if the user is logged in
// and to verify the JWT token
const loginStatus = asyncHandler(async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json(false);
  }
  const verified = jwt.verify(token, process.env.JWT_SECRET);
  if (verified) {
    const user = await User.findById(verified.id).select("-password");
    if (user) {
      res.json({
        verified: true,
        id: verified.id,
        status: user.status,
        user: user,
        token: token,
      });
    }
  }

  return res.json(false);
});

// Get User Details Controller
const getUserDetails = asyncHandler(async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const verified = jwt.verify(token, process.env.JWT_SECRET);
  if (!verified) {
    return res.status(401).json({ message: "Invalid token" });
  }

  const user = await User.findById(verified.id).select("-password");
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  return res.status(200).json(user);
});

//forgot password controllers
const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ message: "User not found." });

  // Generate token
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
    expiresIn: "15m",
  });

  // Optionally save hashed token + expiry to DB (optional)
  user.resetPasswordToken = token;
  user.resetPasswordExpires = Date.now() + 15 * 60 * 1000; // 15 mins
  await user.save();

  await sendPasswordResetEmail(user);

  res.json({ message: "Password reset link sent to your email." });
});

//verify reset password token
const verifyResetToken = asyncHandler(async (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ message: "Token is required." });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (
      !user ||
      user.resetPasswordToken !== token ||
      user.resetPasswordExpires < Date.now()
    ) {
      return res.status(400).json({ message: "Invalid or expired token." });
    }

    res.json({ message: "Token is valid." });
  } catch (err) {
    res.status(400).json({ message: "Invalid or expired token." });
  }
});

//reset password controller
const resetPassword = asyncHandler(async (req, res) => {
  const { token, newPassword } = req.body;

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (
      !user ||
      user.resetPasswordToken !== token ||
      user.resetPasswordExpires < Date.now()
    ) {
      return res.status(400).json({ message: "Invalid or expired token." });
    }

    user.password = newPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    await sendResetSuccessEmail(user);

    res.json({ message: "Password reset successful." });
  } catch (err) {
    res.status(400).json({ message: "Invalid or expired token." });
  }
});

// Change Password Controller
const changePassword = asyncHandler(async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const user = await User.findById(verified.id);
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  const isMatch = await bcrypt.compare(oldPassword, user.password);
  if (!isMatch) {
    return res.status(400).json({ message: "Old password is incorrect" });
  }

  user.password = newPassword;
  await user.save();

  return res.status(200).json({ message: "Password changed successfully" });
});

// Log Out Controller
const logOut = asyncHandler(async (req, res) => {
  res.cookie("token", "", {
    path: "/",
    httpOnly: true,
    expires: new Date(0),
    sameSite: "none",
    secure: true,
  });
  return res.status(200).json({ message: "Successfully Logged Out" });
});

module.exports = {
  registerAdmin,
  registerUser,
  verifyEmail,
  login,
  changePassword,
  forgotPassword,
  verifyResetToken,
  resetPassword,
  loginStatus,
  getUserDetails,
  logOut,
};
