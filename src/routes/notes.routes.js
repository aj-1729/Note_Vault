import { Router } from "express";
import { verifyJWT } from "../../middlewares/auth.middlewares.js";
import { createNote } from "../controllers/notes.controllers.js";

const router = Router();

router.route("/create").post(verifyJWT,createNote)

export default router