import mongoose, { STATES } from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";




const userSchema = new mongoose.Schema(
    {
        usernname:{
            type: String,
            required: [true, 'Username is required'],
            unique: true,
            trim: true,
            minlength: 3
        },
        email:{
            type: String,
            required: [true, 'Email is required'],
            unique: true,
            trim: true,
            lowercase: true
        },
        password:{
            type: String,
            required: [true, 'Password is required'],
            minlength: 6,
            select: false
        }
    },
    {
        timestamps = true
    }
)

userSchema.pre("save", async function (next) {
    if(!this.isModified("password")) return;

    this.password = await bcrypt.hash(this.password, 10);
})

userSchema.methods.isPasswordCorrect = async function(password)
{
    return await bcrypt.compare(password,this.password);
}


const User = mongoose.model("User", userSchema);

export {User};