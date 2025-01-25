// Import necessary modules
// Import necessary modules
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const Joi = require('joi');

const app = express();
const port = process.env.PORT || 8080;

// MongoDB Connection
const mongoURI = 'mongodb://localhost:27017/auth'; 
mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB Connected'))
  .catch(err => console.error(err));

// Middleware
app.use(bodyParser.json());

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, maxlength: 255 },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'user'], default: 'user' }
});

const User = mongoose.model('User', userSchema);

// Entry Schema
const entrySchema = new mongoose.Schema({
  title: { type: String, required: true, maxlength: 255 },
  description: { type: String },
  // ... other fields
});

const Entry = mongoose.model('Entry', entrySchema);

// Validation Schemas
const entrySchemaJoi = Joi.object({
  title: Joi.string().required().max(255),
  description: Joi.string().allow(''), 
  // ... other field validations
});

const loginSchemaJoi = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required()
});

// Role Middleware
const authorize = (roles) => (req, res, next) => {
  if (roles.includes(req.user.role)) {
    next();
  } else {
    res.status(403).json({ message: 'Forbidden' });
  }
};

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, 'your_secret_key', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Routes
app.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10); 

    const user = new User({ name, email, password: hashedPassword });
    await user.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error registering user' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id, role: user.role }, 'abcd');
    res.json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error logging in' });
  }
});

app.post('/create', authenticateToken, authorize(['admin']), async (req, res) => {
  try {
    const { error } = entrySchemaJoi.validate(req.body);
    if (error) return res.status(400).json({ message: error.details[0].message });

    const entry = new Entry(req.body);
    await entry.save();

    res.status(201).json(entry);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error creating entry' });
  }
});

app.get('/all', authenticateToken, async (req, res) => {
  try {
    const entries = await Entry.find();
    res.json(entries);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error retrieving entries' });
  }
});
app.get('/',async(req,res) =>{
  res.render("Backend is working.Check it through postman.")
}

app.get('/byId/:id', authenticateToken, async (req, res) => {
  try {
    const entry = await Entry.findById(req.params.id);
    if (!entry) return res.status(404).json({ message: 'Entry not found' });
    res.json(entry);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error retrieving entry' });
  }
});

app.put('/update/:id', authenticateToken, authorize(['admin']), async (req, res) => {
  try {
    const { error } = entrySchemaJoi.validate(req.body);
    if (error) return res.status(400).json({ message: error.details[0].message });

    const entry = await Entry.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!entry) return res.status(404).json({ message: 'Entry not found' });
    res.json(entry);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error updating entry' });
  }
});

app.delete('/delete/:id', authenticateToken, authorize(['admin']), async (req, res) => {
  try {
    const entry = await Entry.findByIdAndDelete(req.params.id);
    if (!entry) return res.status(404).json({ message: 'Entry not found' });
    res.json({ message: 'Entry deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error deleting entry' });
  }
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
