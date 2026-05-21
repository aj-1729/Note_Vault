import { Router } from "express";

import { registerUser, verifyEmail } from "../controllers/user.controllers";

const router = Router()


router.route("/register").post(registerUser);
//router.route("/login").post(loginUser);
router.route("/verify/:token").get(verifyEmail);


export default router