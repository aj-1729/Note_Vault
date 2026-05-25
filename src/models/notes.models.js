import mongoose, { trusted } from "mongoose";

const noteSchema = new mongoose.Schema(
    {
        title:{
            type: String,
            required: true 
        },
        content:{
            type: String,
            required: true
        },
        owner:{
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true
        },
        tags: [
            {
                type: String,
            }
        ],
    },{timestamps: true}
);

export const Note = mongoose.model("Notes", noteSchema); 