const express = require("express");
const router = express.Router();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const connectToDatabase = require("../models/db");
const dotenv = require("dotenv");
const pino = require("pino");
dotenv.config();

const logger = pino();

router.post("/register", async (req, res) => {
    try {
        const db = await connectToDatabase();

        const collection = db.collection("users");

        const existingEmail = await collection.findOne({ email: req.body.email });

        if (existingEmail) {
            logger.error("Email id already exists");
            res.status(400).json({ error: "Email id already exists" });
        }

        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(req.body.password, salt);

        const newUser = await collection.insertOne({
            email: req.body.email,
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            password: hash,
            createdAt: new Date(),
        })

        const payload = {
            user: {
                id: newUser.insertedId,
            },
        };

        const authtoken = jwt.sign(payload, process.env.JWT_SECRET);

        logger.info("User registered successfully");
        res.json({
            authtoken,
            email
        })
    } catch (error) {
        res.status(500).send("Internal Server Error");
    }
})

module.exports = router;