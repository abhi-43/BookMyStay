import User from "../models/User.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { createError } from "../utils/error.js";

export const register = async (req, res, next) => {
    try {

        const salt = bcrypt.genSaltSync(10);
        const hash = bcrypt.hashSync(req.body.password, salt);

        const newUser = new User({
            ...req.body,
            password: hash,
        });

        await newUser.save();
        res.status(200).send("User Created");
    }
    catch(err){
        next(err);
    }
};

export const login = async (req, res, next) => {
    try {
        console.log("abc", req.body);
        const user = await User.findOne({ email: req.body.email });
        console.log(user, "PARWAIZ");
        if(!user)
            return next(createError(404, "User Not Found"));

        const isPasswordCorrect = await bcrypt.compare(req.body.password, user.password)
        console.log(isPasswordCorrect);
        if(!isPasswordCorrect)
            return next(createError(400, "Wrong Credentials"));

            const token = jwt.sign({ id: user._id, isAdmin: user.isAdmin }, process.env.JWT);

        const { password, isAdmin, ...otherDetails } = user._doc;
       
        res.cookie("access_token", token, {httpOnly: true}).status(200).json({ details: { ...otherDetails }, isAdmin });
    }
    catch(err) {
        next(err);
    }
};