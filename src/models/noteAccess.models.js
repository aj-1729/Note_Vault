import mongoose from "mongoose";

const noteAccessSchema = new mongoose.Schema(
    {
        note: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Notes",
            required: true
        },
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true
        },
        role: {
            type: String,
            enum: ["viewer", "editor"],
            required: true
        },
        invitedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true
        },
        status: {
            type: String,
            enum: ["pending", "accepted", "revoked"],
            default: "accepted"
        }
    },
    { timestamps: true }
);


noteAccessSchema.index({ note: 1, user: 1 }, { unique: true });

export const NoteAccess = mongoose.model("NoteAccess", noteAccessSchema);