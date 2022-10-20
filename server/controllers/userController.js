const db = require('../models');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

class UserController {
    static async register(req, res) {
        //regex email validation
        const emailRegex = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
        //regex password validation
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/;
        console.log(req.body);
        const { firstName, lastName, username, email, password } = req.body;
        if (!firstName || !lastName || !username || !email || !password) {
            return res.status(400).json({ message: "All fields are required" });
        }
        if (!emailRegex.test(email)) {
            return res.status(400).json({ message: "Invalid email" });
        }
        if (!passwordRegex.test(password)) {
            return res.status(400).json({ message: "Password must contain at least 8 characters, 1 uppercase, 1 lowercase and 1 number" });
        }
        try {
            const user = await db.User.findOne({ where: { email } });
            if (user) {
                return res.status(400).json({ message: "Email already exists" });
            }
            const hashedPassword = await bcrypt.hash(password, 10);
            const newUser = await db.User.create({
                firstName,
                lastName,
                username,
                email,
                password: hashedPassword
            });
            // const token = jwt.sign({ id: newUser.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
            return res.status(201).json({ user: newUser });
        } catch (err) {
            console.log(err);
            return res.status(500).json({ message: "Something went wrong" });
        }
    }

    

    static async login(req, res) {
         //regex email validation
         const emailRegex = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
         //regex password validation
         const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/;
            console.log(req.body);
            const { email, password } = req.body;
            if (!email || !password) {
                return res.status(400).json({ message: "All fields are required" });
            }
            if (!emailRegex.test(email)) {
                return res.status(400).json({ message: "Invalid email" });
            }
            if (!passwordRegex.test(password)) {
                return res.status(400).json({ message: "Password must contain at least 8 characters, 1 uppercase, 1 lowercase and 1 number" });
            }
            try {
                const user = await db.User.findOne({ where: { email } });
                if (!user) {
                    return res.status(400).json({ message: "Invalid credentials" });
                }
                const isMatch = await bcrypt.compare(password, user.password);
                if (!isMatch) {
                    return res.status(400).json({ message: "Invalid credentials" });
                }
                const token = jwt.sign({ id: user.id }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
                return res.status(200).json({ token, user });
            } catch (err) {
                console.log(err);
                return res.status(500).json({ message: "Something went wrong" });
            }
        }
    

    static async getUser(req, res) {
        const user = await db.User.findOne({
            where: {
                id: req.user.id
            }
        });
        res.json(user);
    }


    static async getAllUsers(req, res) {
        const users = await db.User.findAll(
            {
                attributes: ['id', 'username', 'firstName', 'lastName']
            }
        );
        res.json(users);
    }

    static async deleteUser(req, res) {
        const user = await db.User.findOne({
            where: {
                id: req.params.id
            }
        });
        if (user) {
            await user.destroy();
            res.json({ message: 'User deleted' });
        } else {
            res.status(404).json({ message: 'User not found' });
        }
    }

    //get user by id
    static async getUserById(req, res) {
        const user = await db.User.findOne({
            where: {
                id: req.params.id
            }
        });
        if (user) {
            res.json(user);
        } else {
            res.status(404).json({ message: 'User not found' });
        }
    }

    //update user
    static async updateUser(req, res) {
        const user = await db.User.findOne({
            where: {
                id: req.params.id
            }
        });
        if (user) {
            await user.update(req.body);
            res.json(user);
        } else {
            res.status(404).json({ message: 'User not found' });
        }
    }
    

        
}

module.exports = UserController;