import { User } from "../models/users.models.js";
import ApiError from "../utils/Apierror.js";
import Apiresponse from "../utils/Apiresponse.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import crypto from "node:crypto";
import bcrypt from "bcryptjs";

const generateAccessRefreshToken = async(userId) => 
{
    try {
        const user = await User.findById({userId});

        const accessToken = await user.generateAccessToken();
        const refreshToken = await user.generateRefreshToken();

        user.refreshToken = refreshToken;

        await user.save({validateBeforeSave: false});

    
        return {accessToken, refreshToken};
    } catch (error) {
        throw new ApiError(500, "Something went wrong will generating RAT");
    }
}

const registerUser = asyncHandler(
    async(req,res)=>
    {
        const {email,username,password} = req.body;

        if(email === "" || password === "" || username === "")
            throw new ApiError(402, "All feilds are requiered!!");

        const userExists = await User.findOne({
            $or: [{ email: email }, { username: username }]
        });
        

        if(userExists)
            throw new ApiError(402, "This email already exits");

        const verificationToken = crypto.randomBytes(20).toString('hex');

        const user = new User(
            {
                username,
                email,
                password,
                verificationToken,
                verificationTokenExpire: Date.now() + 24 * 60 * 60 * 1000
            }
        );

        await user.save();

        if(!user)
            throw new ApiError(400, "User data invalid");

        const verifyUrl = `http://localhost:8000/api/v1/users/verify/${verificationToken}`;
        console.log(verifyUrl)

       // user.select("-password -verificationToken")


        return res.status(200).json(
            new Apiresponse(202,"User registered!!, check the terminal for verification link!",{user}
            )
                 
        )
    }
)

const verifyEmail = asyncHandler(
    async(req,res)=>
    {
        const user = await User.findOne(
            {
                verificationToken : req.params.token,
                verificationTokenExpire : {$gt: Date.now()}
            }
        )


        if(!user)
            throw new ApiError(402, "Invalid token or expired token");

        user.isVerified = true;
        user.verificationToken = undefined;
        user.verificationTokenExpire = undefined;

        await user.save();

        res.status(200)
        .json(
            new Apiresponse(202, "User created successfully", {user})
        )
    }
)

const loginUser = asyncHandler(
    async(req,res)=>
    {
        const{email, password}=req.body;

        if(!email || !password)
            throw new ApiError(402,"all fields are requiered");

        const user = await User.findOne({email})

        if(!user)
            throw new ApiError(402,"user not found");

        if(!user.isVerified)
            throw new ApiError(404,"Email is not verified!!!")

        const isPasswordCorrect = await bcrypt.compare(password, user.password);

        if(!isPasswordCorrect)
            throw new ApiError(404,"Incorrect Password");

        const {accessToken,refreshToken} = generateAccessRefreshToken(user._id);
    }
)
export{registerUser,
verifyEmail,
loginUser,
}