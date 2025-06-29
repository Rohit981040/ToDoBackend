// Import required modules const express = require("express"); const mongoose = require("mongoose"); const jwt = require("jsonwebtoken"); const bcrypt = require("bcryptjs"); const app = express(); // Load environment variables const PORT = process.env.PORT || 8000; const MONGOURL = process.env.MONGOURL; // Middleware to parse JSON bodies app.use(express.json()); app.use( cors({ origin: "*", }) ); // Connect to MongoDB mongoose.connect(MONGOURL, { useNewUrlParser: true, useUnifiedTopology: true, }); // Define User schema and model const userSchema = new mongoose.Schema({ username: String, password: String, }); const User = mongoose.model("User", userSchema); // Define Task schema and model const taskSchema = new mongoose.Schema({ text: String, status: String, priority: String, userId: mongoose.Schema.Types.ObjectId, }); const Task = mongoose.model("Task", taskSchema); // Register route app.post("/register", async (req, res) => { try { const { username, password } = req.body; const hashed = await bcrypt.hash(password, 10); const user = new User({ username, password: hashed }); await user.save(); res.status(201).json({ message: "User registered successfully" }); } catch (err) { res.status(500).json({ error: "Registration failed" }); } }); // Login route app.post("/login", async (req, res) => { try { const { username, password } = req.body; const user = await User.findOne({ username }); if (!user) return res.status(400).json({ error: "Invalid credentials" }); const isMatch = await bcrypt.compare(password, user.password); if (!isMatch) return res.status(400).json({ error: "Invalid credentials" }); const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "1h", }); res.json({ message: "Login successful", token }); } catch (err) { res.status(500).json({ error: "Login failed" }); } }); // JWT authentication middleware const authMiddleware = (req, res, next) => { const authHeader = req.headers.authorization; if (!authHeader || !authHeader.startsWith("Bearer ")) { return res.status(401).json({ error: "Access denied. No token provided." }); } const token = authHeader.split(" ")[1]; try { const decoded = jwt.verify(token, process.env.JWT_SECRET); req.user = decoded; next(); } catch (err) { res.status(401).json({ error: "Invalid or expired token." }); } }; // Get all tasks for the authenticated user app.get("/task", authMiddleware, async (req, res) => { const tasks = await Task.find({ userId: req.user.userId }); res.json(tasks); }); // Create a new task for the authenticated user app.post("/tasks", authMiddleware, async (req, res) => { const task = new Task({ ...req.body, userId: req.user.userId }); await task.save(); res.status(201).json({ message: "Task created", task }); }); // Delete a task by ID (only if it belongs to the user) app.delete("/task/:id", authMiddleware, async (req, res) => { const deleted = await Task.findOneAndDelete({ _id: req.params.id, userId: req.user.userId, }); if (!deleted) { return res.status(404).json({ error: "Task not found or unauthorized" }); } res.json({ message: "Task deleted successfully" }); }); //update status of the Task app.patch("/task/:id/status", authMiddleware, async (req, res) => { const { status } = req.body; const task = await Task.findOneAndUpdate( { _id: req.params.id, userId: req.user.userId }, { status }, { new: true } ); if (!task) return res.status(404).json({ message: "Task Not Found" }); res.json(task); }); //change the priority of the task app.patch("/task/:id/priority", authMiddleware, async (req, res) => { const { priority } = req.body; const task = await Task.findOneAndUpdate( { _id: req.params.id, userId: req.user.userId }, { priority }, { new: true } ); if (!task) return res.status(404).json({ message: "Task Not Found" }); res.json(task); });
const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 8000;
const MONGOURL = process.env.MONGOURL;

app.use(express.json());

app.use(
  cors({
    origin: "*",
  })
);

mongoose.connect(MONGOURL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
});
const User = mongoose.model("User", userSchema);

const taskSchema = new mongoose.Schema({
  text: String,
  status: String,
  priority: String,
  userId: mongoose.Schema.Types.ObjectId,
});
const Task = mongoose.model("Task", taskSchema);

app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashed });
    await user.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.json({ message: "Login successful", token });
  } catch (err) {
    res.status(500).json({ error: "Login failed" });
  }
});

const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid or expired token." });
  }
};

app.get("/task", authMiddleware, async (req, res) => {
  const tasks = await Task.find({ userId: req.user.userId });
  res.json(tasks);
});

app.post("/tasks", authMiddleware, async (req, res) => {
  const task = new Task({ ...req.body, userId: req.user.userId });
  await task.save();
  res.status(201).json({ message: "Task created", task });
});

app.delete("/task/:id", authMiddleware, async (req, res) => {
  const deleted = await Task.findOneAndDelete({
    _id: req.params.id,
    userId: req.user.userId,
  });

  if (!deleted) {
    return res.status(404).json({ error: "Task not found or unauthorized" });
  }

  res.json({ message: "Task deleted successfully" });
});

app.patch("/task/:id/status", authMiddleware, async (req, res) => {
  const { status } = req.body;
  const task = await Task.findOneAndUpdate(
    { _id: req.params.id, userId: req.user.userId },
    { status },
    { new: true }
  );
  if (!task) return res.status(404).json({ message: "Task Not Found" });
  res.json(task);
});

app.patch("/task/:id/priority", authMiddleware, async (req, res) => {
  const { priority } = req.body;
  const task = await Task.findOneAndUpdate(
    { _id: req.params.id, userId: req.user.userId },
    { priority },
    { new: true }
  );
  if (!task) return res.status(404).json({ message: "Task Not Found" });
  res.json(task);
});

app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
