import { findUserByEmailOrUsername, createUser } from "../repositories/user.repository.js";
import ApiError from "../utils/Apierror.js";
import crypto from "node:crypto";
import { findUserByVerificationToken, updateUser } from "../repositories/user.repository.js";


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

export const verifyUserService = async (token) => {
    // 1. Ask the repository to find the user
    const user = await findUserByVerificationToken(token);

    // 2. Business Logic: If no user is found, the token is fake or expired
    if (!user) {
        throw new ApiError(400, "Invalid or expired verification token");
    }

    // 3. Business Logic: Mark as verified and wipe the old tokens
    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationTokenExpire = undefined;

    // 4. Save and return
    return await updateUser(user);
};