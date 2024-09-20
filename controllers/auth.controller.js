import bcrypt from "bcrypt";
import prisma from "../lib/prisma.js";
import jwt from "jsonwebtoken";

export const register = async (req, res) => {
    const {username, email, password} = req.body;

try{
    //HASHING PASSWORD
    const hashedPassword = await bcrypt.hash(password, 10);

    console.log(hashedPassword);

    //CREATE NEW USER & SAVE TO DATABASE
    const newUser = await prisma.user.create({
        data:{
            username, email, password:hashedPassword,
        },
    });
    console.log(newUser);

    res.status(201).json({message:"user created successfully"});
}catch (err){
    console.log(err)
    res.status(500).json({message: "failed to create user"});
    }
}



export const login = async (req, res) => {
    //db operations here bro
    const {username, password} = req.body;

    try{
        //checking if the user does exists bro haha
        const user = await prisma.user.findUnique({
            where:{username}
        })

        if(!user) return res.status(401).json({message: "Invalid credentials"});

        //if the password is correct 
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if(!isPasswordValid) return res.status(401).json({message: "Invalid Credentials"});

        //generate a cookie token and then send to user
        //res.setHeader("Set-Cookie", "test=" + "myValue").json("success");
        const age = 1000 * 60 * 60 * 24 * 7

        const token = jwt.sign({
            id:user.id
        }, process.env.JWT_SECRET_KEY,{expiresIn: age})
        
        res.cookie("token", token, {
            httpOnly:true,
            //if we are on production we should make the secure to true
            //secure:true
            maxAge: age,
        })
        .status(200)
        .json({message: "login successful"});
    } catch (err){
        console.log(err);
        res.status(500).json({message:" Failed to login"})
    }
    
}

export const logout = (req, res) => {
    res.clearCookie("token").status(200).json({message: "Logout Successful"});
}