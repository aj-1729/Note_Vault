import { findUserByEmailOrUsername, createUser } from "../repositories/user.repository.js";
import ApiError from "../utils/Apierror.js";
import crypto from "node:crypto";


export const registerUserService = async (userData) => {
    const exisitingUser = await findUserByEmailOrUsername(userData.email, userData.username);

    if (exisitingUser) {
        throw new ApiError(400, "User already exists!");
    }

    const verificationToken = crypto.randomBytes(40).toString("hex");
    const verificationTokenExpiry = Date.now() + 24 * 60 * 60 * 1000;

    const userToSave =
    {
        ...userData,
        verificationToken,
        verificationTokenExpiry,
        isVerified: false
    }


    const savedUser = await createUser(userToSave);

    return { savedUser, verificationToken };

};