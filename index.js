require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.json());

mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

// webtoon model
const webtoonSchema = new mongoose.Schema({
  title: { type: String, required: true, index: true },
  description: { type: String, required: true },
  summary: { type: String, required: true },
  characters: [{ type: String, index: true }]
});

webtoonSchema.index({ title: 'text', description: 'text', summary: 'text' });

const Webtoon = mongoose.model('Webtoon', webtoonSchema);


const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);


const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (token == null) return res.sendStatus(401);
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});

app.use("/api/", apiLimiter);

// get all webtoons
app.get('/api/webtoons', async (req, res) => {
  try {
    const webtoons = await Webtoon.find({}, 'title description characters');
    res.json(webtoons);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


// create webtoon
app.post('/api/webtoons', authenticateToken, async (req, res) => {
  const webtoon = new Webtoon({
    title: req.body.title,
    description: req.body.description,
    summary: req.body.summary,
    characters: req.body.characters
  });

  try {
    const newWebtoon = await webtoon.save();
    res.status(201).json(newWebtoon);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});


// get webtoons
app.get('/api/webtoons/:id', async (req, res) => {
  try {
    const webtoon = await Webtoon.findById(req.params.id);
    if (webtoon == null) {
      return res.status(404).json({ message: 'Webtoon not found' });
    }
    res.json(webtoon);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// delete webtoons
app.delete('/api/webtoons/:id', authenticateToken, async (req, res) => {
    try {
      const result = await Webtoon.findByIdAndDelete(req.params.id);
      if (!result) {
        return res.status(404).json({ message: 'Webtoon not found' });
      }
      res.json({ message: 'Webtoon deleted successfully' });
    } catch (err) {
      res.status(500).json({ message: err.message });
    }
  });

//register
app.post('/api/register', async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({
      username: req.body.username,
      password: hashedPassword
    });
    await user.save();
    res.status(201).json({ message: 'User created successfully' });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// login 
app.post('/api/login', async (req, res) => {
  const user = await User.findOne({ username: req.body.username });
  if (user == null) {
    return res.status(400).json({ message: 'Cannot find user' });
  }
  try {
    if (await bcrypt.compare(req.body.password, user.password)) {
      const accessToken = jwt.sign(user.toJSON(), process.env.JWT_SECRET);
      res.json({ accessToken: accessToken });
    } else {
      res.status(401).json({ message: 'Invalid credentials' });
    }
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));