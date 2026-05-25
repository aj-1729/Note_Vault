import { User } from "../src/models/users.models.js";
import ApiError from "../src/utils/Apierror.js";
import { asyncHandler } from "../src/utils/asyncHandler.js";
import jwt from "jsonwebtoken"

const verifyJWT = asyncHandler(
    async(req, res, next) =>
    {
        try {
            const token = req.cookies?.accessToken;
    
            if(!token) 
                throw new ApiError(402,"Unauthorized Access");
    
            const decodedToken = await jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    
            const user = await User.findById(decodedToken?._id).select("-password -refreshToken");
    
            if(!user)
                throw new ApiError(402, "Unauthorized Access");
    
            req.user = user;
            next();
        } catch (error) {
            console.log(error);
            throw new ApiError(403,"Something is wrong!!");
        }
    }
)

export {verifyJWT}