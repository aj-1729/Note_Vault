import { Note } from "../models/notes.models.js";
import ApiError from "../utils/Apierror.js";
import Apiresponse from "../utils/Apiresponse.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { uploadToCloudinary } from "../utils/cloudinary.js";
// Import 'io' from your index.js file
import { io } from "../../index.js";
import Redis from "ioredis";

const redis = new Redis();


const createNote = asyncHandler(
    async (req, res) => {
        const { title, content, tags } = req.body;

        if (!title || !content)
            throw new ApiError(404, "Both title and contents are reqiuered");

        const contentUrl = await uploadToCloudinary(content);

        if (!contentUrl)
            throw new ApiError(500, "error saving the notes!! ");
        const note = await Note.create({
            title,
            content: contentUrl,
            tags: tags || [],
            owner: req.user._id,
        })

        if (!note)
            throw new ApiError(501, "Failed to save the note");


        await redis.del(`notes:${req.user._id}`);


        io.to(req.user._id.toString()).emit("vault_updated", { message: "Note created!" });
        return res
            .status(200)
            .json(
                new Apiresponse(200, "yay note created", { note })
            );
    }
)

const getUserNote = asyncHandler(
    async (req, res) => {




        const cacheKey = `notes:${req.user._id}`;

        const cachedNotes = await redis.get(cacheKey);

        if (cachedNotes) {
            console.log("Coming from redis server");

            return res.status(200).json(
                new Apiresponse(202,
                    "Notes fetched successfully",
                    {
                        note: JSON.parse(cachedNotes)
                    }
                )
            )
        }


        const note = await Note.find({ owner: req.user._id }).sort({ createdAt: -1 });

        if (!note)
            throw new ApiError(402, "Something went wrong while fetching the notes!!");

        await redis.set(cacheKey, JSON.stringify(note), 'EX', 3600);

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
    async (req, res) => {
        const { noteId } = req.params;
        const { title, content, tags } = req.body;

        const note = await Note.findOne({ _id: noteId, owner: req.user._id });

        if (!note)
            throw new ApiError(402, "Note Not found / invalid permisiions");

        if (title) note.title = title;

        if (tags) note.tags = tags;

        if (content) {

            const newContentUrl = await uploadToCloudinary(content);

            if (!newContentUrl) {
                throw new ApiError(500, "Failed to upload updated note to secure storage");
            }

            note.content = newContentUrl;
        }

        await note.save();

        await redis.del(`notes:${req.user._id}`);
        io.to(req.user._id.toString()).emit("vault_updated", { message: "Note updated!" });
        return res.
            status(200)
            .json(
                new Apiresponse(202, "Note updated Successfully!!", { note })
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

    await redis.del(`notes:${req.user._id}`);

    io.to(req.user._id.toString()).emit("vault_updated", { message: "Note deleted!" });
    return res.status(200).json(
        new Apiresponse(200, "Note deleted successfully!", {})
    );
})


export {
    createNote,
    getUserNote,
    updateNote,
    deleteNote
}