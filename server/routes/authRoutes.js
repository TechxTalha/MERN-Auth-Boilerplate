const express = require("express");
const protect = require("../middlewares/authenticationMiddleware");
const {
  logOut,
  loginStatus,
  changePassword,
  login,
  getUserDetails,
  registerAdmin,
  registerUser,
  verifyEmail,
  forgotPassword,
  verifyResetToken,
  resetPassword,
} = require("../controllers/authController");
const router = express.Router();

router.post("/register/admin", registerAdmin);
router.post("/register", registerUser);
router.get("/verify-email", verifyEmail);
router.post("/login", login);
router.get("/change-password", protect, changePassword);
router.post("/forgot-password", forgotPassword);
router.post("/verify-reset-token", verifyResetToken);
router.post("/reset-password", resetPassword);
router.get("/loggedin-status", loginStatus);
router.get("/logout", logOut);
router.get("/user-details", protect, getUserDetails);

module.exports = router;
