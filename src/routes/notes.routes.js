import { Router } from "express";
import { verifyJWT } from "../../middlewares/auth.middlewares.js";
import { createNote, getUserNote } from "../controllers/notes.controllers.js";

const router = Router();

router.route("/create").post(verifyJWT,createNote)
router.route("/all").get(verifyJWT,getUserNote)

export default router