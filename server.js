const express = require('express');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 5000;

app.use(cors({
  origin: 'http://localhost:4200', // Adjust this based on your Angular app's URL
  credentials: true // Allow credentials to be sent
}));
app.use(express.json());

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/bookstore', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// User Schema
const userSchema = new mongoose.Schema({
  username: String,
  password: String, // Store hashed password
});

const User = mongoose.model('User', userSchema);

// Book Schema
const bookSchema = new mongoose.Schema({
  title: String,
  author: String,
  price: Number,
  imageUrl: String,
});

const Book = mongoose.model('Book', bookSchema);

// Registration Route
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;

  // Check if the user already exists
  const existingUser = await User.findOne({ username });
  if (existingUser) {
    return res.status(400).json({ message: 'User already exists' });
  }

  // Hash the password before saving
  const hashedPassword = await bcrypt.hash(password, 10);

  // Create and save the new user
  const user = new User({ username, password: hashedPassword });
  await user.save();

  res.json({ message: 'User registered successfully' });
});

// Login Route
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  // Check if the user exists
  const user = await User.findOne({ username });
  if (!user) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }

  // Compare passwords
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }

  // If login is successful, return success message
  res.json({ message: 'Login successful' });
});

// Middleware to verify login credentials for accessing books
const authMiddleware = async (req, res, next) => {
  const { username, password } = req.headers;

  if (!username || !password) {
    return res.status(401).json({ message: 'Username and password required' });
  }

  // Check if the user exists
  const user = await User.findOne({ username });
  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  // Compare passwords
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  next(); // Move on to the next middleware/route handler
};

// Route to get all books (protected by authMiddleware)
app.get('/api/books', authMiddleware, async (req, res) => {
  const books = await Book.find();
  res.json(books);
});

// Route to add a book (protected by authMiddleware)
app.post('/api/books', authMiddleware, async (req, res) => {
  const book = new Book(req.body);
  await book.save();
  res.json(book);
});

// Route to delete a book (protected by authMiddleware)
app.delete('/api/books/:id', authMiddleware, async (req, res) => {
  await Book.findByIdAndDelete(req.params.id);
  res.sendStatus(204);
});

// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
