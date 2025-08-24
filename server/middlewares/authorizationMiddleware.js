const User = require("../models/userModel");

/**
 * Role-based Authorization Middleware
 *
 * Usage:
 *   router.get("/admin", protect, authorizeRoles("admin"), handler);
 *
 * - Checks if the logged-in user has at least one of the allowed roles
 * - Special case: if user has a role with "*" permission, bypasses all checks
 */
function authorizeRoles(...allowedRoles) {
  return async (req, res, next) => {
    try {
      if (!req.user) return res.status(401).json({ message: "Unauthorized" });

      const user = await User.findById(req.user._id).populate("roles");
      if (!user) return res.status(401).json({ message: "User not found" });

      const userRoles = user.roles.map((r) => r.name);

      // Super Admin bypass (any role with "*" permission)
      const isSuperAdmin = user.roles.some((r) => r.permissions.includes("*"));
      if (isSuperAdmin) return next();

      // Check role match
      const hasRole = allowedRoles.some((role) => userRoles.includes(role));
      if (!hasRole) {
        return res
          .status(403)
          .json({ message: "Forbidden: Missing required role" });
      }

      next();
    } catch (err) {
      console.error("Authorization error:", err);
      res.status(500).json({ message: "Internal Server Error" });
    }
  };
}

/**
 * Permission-based Authorization Middleware
 *
 * Usage:
 *   router.get("/reports", protect, authorizePermissions("viewReports"), handler);
 *
 * - Checks if the logged-in user has ALL required permissions
 * - Special case: if user has "*" permission, bypasses all checks
 */
function authorizePermissions(...requiredPermissions) {
  return async (req, res, next) => {
    try {
      if (!req.user) return res.status(401).json({ message: "Unauthorized" });

      const user = await User.findById(req.user._id).populate("roles");
      if (!user) return res.status(401).json({ message: "User not found" });

      const userPermissions = user.roles.flatMap((role) => role.permissions);

      // Super Admin bypass
      if (userPermissions.includes("*")) return next();

      // Check if user has all required permissions
      const hasPermissions = requiredPermissions.every((p) =>
        userPermissions.includes(p)
      );

      if (!hasPermissions) {
        return res
          .status(403)
          .json({ message: "Forbidden: Missing required permissions" });
      }

      next();
    } catch (err) {
      console.error("Authorization error:", err);
      res.status(500).json({ message: "Internal Server Error" });
    }
  };
}

module.exports = { authorizeRoles, authorizePermissions };
