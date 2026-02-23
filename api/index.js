const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");
require("dotenv").config();

const User = require("../models/User");
const Todo = require("../models/Todo");

const app = express();
app.use(cors());
app.use(express.json());

// MongoDB
mongoose.connect(process.env.MONGO_URI);

// Token helper
function generateAccessToken(user) {
  return jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "15m" });
}

// Auth middleware
function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Register
app.post("/register", async (req, res) => {
  const hash = await bcrypt.hash(req.body.password, 10);
  await User.create({ email: req.body.email, password: hash });
  res.json({ message: "Registered" });
});

// Login
app.post("/login", async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) return res.status(400).json({ msg: "No user" });

  const ok = await bcrypt.compare(req.body.password, user.password);
  if (!ok) return res.status(403).json({ msg: "Wrong password" });

  const accessToken = generateAccessToken(user);
  const refreshToken = jwt.sign({ id: user._id }, process.env.JWT_REFRESH);

  user.refreshToken = refreshToken;
  await user.save();

  res.json({ accessToken, refreshToken });
});

// Refresh token
app.post("/refresh", async (req, res) => {
  const user = await User.findOne({ refreshToken: req.body.refreshToken });
  if (!user) return res.sendStatus(403);

  const accessToken = generateAccessToken(user);
  res.json({ accessToken });
});

// CRUD Todos
app.post("/todos", auth, async (req, res) => {
  const todo = await Todo.create({
    title: req.body.title,
    completed: false,
    userId: req.user.id
  });
  res.json(todo);
});

app.get("/todos", auth, async (req, res) => {
  const todos = await Todo.find({ userId: req.user.id });
  res.json(todos);
});

app.put("/todos/:id", auth, async (req, res) => {
  const todo = await Todo.findOneAndUpdate(
    { _id: req.params.id, userId: req.user.id },
    { title: req.body.title },
    { new: true }
  );
  res.json(todo);
});

app.delete("/todos/:id", auth, async (req, res) => {
  await Todo.deleteOne({ _id: req.params.id, userId: req.user.id });
  res.json({ message: "Deleted" });
});

module.exports = app;
