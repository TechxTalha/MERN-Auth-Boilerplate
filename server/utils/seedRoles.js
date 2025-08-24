const Role = require("../models/rolesModel");
const Permission = require("../models/permissionModel");

// Seed all the roles that are prerequired here once, and at app startup they will be created.
async function seedRoles() {
  //   try {
  //     // Define role templates with permission names
  //     const rolesData = [
  //       {
  //         name: "user",
  //         permissions: ["view_dashboard", "view_profile"],
  //       },
  //       {
  //         name: "admin",
  //         permissions: ["*"],
  //       },
  //     ];
  //     for (const roleData of rolesData) {
  //       // Check if role already exists
  //       const existingRole = await Role.findOne({ name: roleData.name });
  //       if (existingRole) continue;
  //       // Fetch permission IDs by name
  //       const permissions = await Permission.find({
  //         name: { $in: roleData.permissions },
  //       });
  //       // Map them to IDs
  //       const permissionIds = permissions.map((perm) => perm._id);
  //       // Create role with linked permissions
  //       await Role.create({
  //         name: roleData.name,
  //         permissions: permissionIds,
  //       });
  //     }
  //   } catch (err) {
  //     console.error("Error seeding roles:", err);
  //   }
}

module.exports = seedRoles;
