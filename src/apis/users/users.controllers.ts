import { NextFunction, Request, Response } from "express";
import User from "../../models/User";
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
import dotenv from "dotenv"

dotenv.config()

const SALT=10

export const signup = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const { username, password } = req.body

        const userFound = await User.findOne({ username: username })
        if (userFound){
            res.status(400).json({err:"Account already exists"})
            return
        }
        const hashedPassword = await bcrypt.hash(password, SALT)

        const newUser = await User.create({username: username, password: hashedPassword})

        const token = jwt.sign({username: newUser.username, id: newUser._id, role:"admin"},
             process.env.JWT_SECRET || "", {
            expiresIn: "7h"
        })
        res.status(201).json({token: token});
    } catch (err) {
        next(err);
    }
};

export const signin = async (req: Request, res: Response, next: NextFunction) => {
    try {
    } catch (err) {
        next(err);
    }
};

export const getUsers = async (req: Request, res: Response, next: NextFunction) => {
    try {
        const users = await User.find().populate("urls");
        res.status(201).json(users);
    } catch (err) {
        next(err);
    }
};