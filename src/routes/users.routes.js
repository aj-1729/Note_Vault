import { Router } from "express";

import { registerUser, verifyEmail, loginUser, logoutUser } from "../controllers/user.controllers.js";
import { verifyJWT } from "../../middlewares/auth.middlewares.js";

const router = Router()


router.route("/register").post(registerUser);
router.route("/login").post(loginUser);
router.route("/verify/:token").get(verifyEmail);
router.route("/logout").get(verifyJWT,logoutUser)


export default router