const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const app = express();

app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log('Connected to MongoDB')).catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
});
const User = mongoose.model('User', userSchema);

// Job Schema
const jobSchema = new mongoose.Schema({
  title: String,
  postDate: Date,
  applicationStartDate: Date,
  applicationEndDate: Date,
  extendedDate: Date,
  category: String,
  location: String,
  salary: String,
  jobType: String,
  fees: {
    sc_st: Number,
    general: Number,
    ews: Number,
    obc: Number,
    bc: Number,
    female: Number,
  },
  article: String,
  link: String,
});
const Job = mongoose.model('Job', jobSchema);

// Job History Schema
const jobHistorySchema = new mongoose.Schema({
  jobId: mongoose.Schema.Types.ObjectId,
  changes: Object,
  updatedAt: { type: Date, default: Date.now },
});
const JobHistory = mongoose.model('JobHistory', jobHistorySchema);

// Middleware for Authentication
const authMiddleware = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'No token provided' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// Admin Login
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(400).json({ message: 'Invalid credentials' });
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });
  const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// Create or Update Job
app.post('/api/admin/jobs', authMiddleware, async (req, res) => {
  const jobData = req.body;
  try {
    if (jobData._id) {
      // Update existing job
      const existingJob = await Job.findById(jobData._id);
      if (!existingJob) return res.status(404).json({ message: 'Job not found' });
      // Log changes to history
      const changes = {};
      for (const key in jobData) {
        if (JSON.stringify(existingJob[key]) !== JSON.stringify(jobData[key])) {
          changes[key] = { old: existingJob[key], new: jobData[key] };
        }
      }
      if (Object.keys(changes).length > 0) {
        await JobHistory.create({ jobId: existingJob._id, changes });
      }
      const updatedJob = await Job.findByIdAndUpdate(jobData._id, jobData, { new: true });
      res.json(updatedJob);
    } else {
      // Create new job
      const job = new Job(jobData);
      await job.save();
      res.json(job);
    }
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Get All Jobs
app.get('/api/admin/jobs', async (req, res) => {
  try {
    const jobs = await Job.find().sort({ postDate: -1 });
    res.json(jobs);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Get Job History
app.get('/api/admin/jobs/:id/history', authMiddleware, async (req, res) => {
  try {
    const history = await JobHistory.find({ jobId: req.params.id }).sort({ updatedAt: -1 });
    res.json(history);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Initialize Admin User
app.post('/api/admin/setup', async (req, res) => {
  const { username, password } = req.body;
  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) return res.status(400).json({ message: 'User already exists' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();
    res.json({ message: 'Admin user created' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));