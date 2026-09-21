import { User } from "../models/users.models.js";

export const findUserByEmailOrUsername = async (email, username) => {
    return await User.findOne({
        $or: [{ email }, { username }]
    });
};


export const createUser = async (userData) => {
    const user = new User(userData);
    return await user.save();
};

export const findUserByVerificationToken = async (token) => {
    return await User.findOne({
        verificationToken: token,
        verificationTokenExpire: { $gt: Date.now() }
    });
};

export const updateUser = async (user) => {
    return await user.save({ validateBeforeSave: false });
};