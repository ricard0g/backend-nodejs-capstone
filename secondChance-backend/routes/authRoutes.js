const express = require("express");
const { body, validationResult } = require("express-validator");
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
      return res.status(400).json({ error: "Email id already exists" });
    }

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(req.body.password, salt);

    const newUser = await collection.insertOne({
      email: req.body.email,
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      password: hash,
      createdAt: new Date(),
    });

    const payload = {
      user: {
        id: newUser.insertedId,
      },
    };

    const authtoken = jwt.sign(payload, process.env.JWT_SECRET);

    logger.info("User registered successfully");
    res.json({
      authtoken,
      email: req.body.email,
    });
  } catch (error) {
    res.status(500).send("Internal Server Error");
  }
});

router.post("/login", async (req, res) => {
  try {
    const db = await connectToDatabase();

    const collection = db.collection("users");

    const theUser = await collection.findOne({ email: req.body.email });

    if (theUser) {
      let result = await bcrypt.compare(req.body.password, theUser.password);

      if (!result) {
        logger.error("Password not correct");
        return res.status(404).json({ error: "Wrong Password" });
      }

      const userName = theUser.firstName;
      const userEmail = theUser.email;

      let payload = {
        user: {
          id: theUser._id.toString(),
        },
      };
      const authtoken = jwt.sign(payload, process.env.JWT_SECRET);
      logger.info("User logged in successfully");
      return res.status(200).json({ authtoken, userName, userEmail });
    } else {
      logger.error("User not found");
      return res.status(404).json({ error: "User not found" });
    }
  } catch (error) {
    res.status(500).send("Internal Server Error");
  }
});

router.put("/update", async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.error("Validation errors in update request", errors);
    return res.status(400).json({ errors: errors.array() });
  }
  try {
    const email = req.headers.email;

    if (!email) {
      logger.error("Email not found in the request header");
      return res
        .status(400)
        .json({ error: "Email not found in the request header" });
    }

    const db = await connectToDatabase();

    const collection = db.collection("users");

    const existingUser = await collection.findOne({ email });

    if (!existingUser) {
      logger.error("User not found");
      return res.status(404).json({error: "User not found"});
    }

    existingUser.firstName = req.body.name;
    existingUser.updatedAt = new Date();

    const updatedUser = await collection.findOneAndUpdate(
      { email },
      { $set: existingUser },
      { returnDocument: "after" }
    );

    const payload = {
      user: {
        id: updatedUser._id.toString(),
      }
    }

    const authtoken = jwt.sign(payload, process.env.JWT_SECRET);
    logger.info("User updated successfully");
    return res.json({authtoken});
  } catch (error) {
    return res.status(500).send("Internal Server Error");
  }
});

module.exports = router;
