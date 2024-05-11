import express from "express";
const router = express.Router();
import { getAllUsers } from "../controllers/userController.js";
import {
  signUp,
  login,
  logout,
  checkToken,
  checkRole,
} from "../controllers/authController.js";

router.post("/signup", signUp);
router.post("/login", login);
router.post("/logout", checkToken, logout);
router.get("/users", checkToken, checkRole(["admin", "manager"]), getAllUsers);

export default router;
