import { User } from "../models/users.models";
import ApiError from "../utils/Apierror";
import Apiresponse from "../utils/Apiresponse";
import { asyncHandler } from "../utils/asyncHandler";


const registerUser = asyncHandler(
    async(req,res)=>
    {
        const {email,username,password} = req.body;
        if(email === "" || password === "" || username === "")
            throw new ApiError(402, "All feilds are requiered!!");

        const userExists = await User.findOne({email:email});
        

        if(userExists)
            throw new ApiError(402, "This email already exits");

        const verificationToken = crypto.randomBytes(20).toString('hex');

        const user = await User(
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

        const verifyUrl = `http://localhost:5000/api/v1/users/verify/${verificationToken}`;
        console.log(verifyUrl)


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
                verificationToken = req.params.token,
                verificationTokenExpire = {$gt: Date.now()}
            }
        )


        if(!user)
            return new ApiError(402, "Invalid token or expired token");

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

export{registerUser}