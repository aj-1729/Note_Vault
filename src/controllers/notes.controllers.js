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

const getUserNote = asyncHandler(
    async(req,res)=>{
        const note = await Note.find({owner: req.user._id}).sort({createdAt:-1});

        if(!note)
            throw new ApiError(402, "Something went wrong while fetching the notes!!");

        return res
        .status(200)
        .json(
            new Apiresponse(202,
                "Notes fetched successfully",
                {
                    note
                }
            )
        )
    }
)

const updateNote = asyncHandler(
    async(req,res)=>
    {
        const {noteId} = req.params;
        const {title, content, tags} = req.body;

        const note = await  Note.findOne({_id: noteId, owner: req.user._id});

        if(!note)
            throw new ApiError(402,"Note Not found / invalid permisiions");

        if(title) note.title = title;
        if(content) note.content = content;
        if(tags) note.tags = tags;

        await note.save();

        return res.
        status(200)
        .json(
            new Apiresponse(202, "Note updated Successfully!!", {note})
        )
    }
)

const deleteNote = asyncHandler(async (req, res) => {
    const { noteId } = req.params;

    // Find the note and delete it ONLY if the logged-in user owns it
    const note = await Note.findOneAndDelete({ _id: noteId, owner: req.user._id });

    if (!note) {
        throw new ApiError(404, "Note not found or you do not have permission to delete it");
    }

    return res.status(200).json(
        new Apiresponse(200, "Note deleted successfully!", {})
    );
})


export {createNote,
    getUserNote,
updateNote,
deleteNote}