import { Router } from "express";
import { verifyJWT } from "../../middlewares/auth.middlewares.js";
import { createNote, deleteNote, getUserNote, updateNote } from "../controllers/notes.controllers.js";

const router = Router();

router.route("/create").post(verifyJWT,createNote)
router.route("/all").get(verifyJWT,getUserNote)
router.route("/update/:noteId").get(verifyJWT,updateNote)
router.route("/delete/:noteId").get(verifyJWT,deleteNote)
export default router