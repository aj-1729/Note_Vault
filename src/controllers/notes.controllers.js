import { Note } from "../models/notes.models.js";
import ApiError from "../utils/Apierror.js";
import Apiresponse from "../utils/Apiresponse.js";
import { asyncHandler } from "../utils/asyncHandler.js";


const createNote = asyncHandler(
    async(req, res)=>{
        const {title, content, tags} = req.body;

        if(!title || !content)
            throw new ApiError(404, "Both title and contents are reqiuered");

        const note = await Note.create({
            title,
            content,
            tags : tags || [],
            owner: req.user._id,
        })

        if(!note)
            throw new ApiError(501,"Failed to save the note");

        return res
        .status(200)
        .json(
            new Apiresponse(200,"yay note created", {note})
        );
    }
)

export {createNote}