const express = require('express');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const { authenticate } = require('../middleware/auth');

const router = express.Router();

/**
 * @swagger
 * /auth/register:
 *   post:
 *     summary: Register a new user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [name, email, password]
 *             properties:
 *               name:
 *                 type: string
 *                 example: John Doe
 *               email:
 *                 type: string
 *                 example: john@example.com
 *               password:
 *                 type: string
 *                 minLength: 6
 *                 example: secret123
 *     responses:
 *       201:
 *         description: User registered successfully
 *       400:
 *         description: Validation error or email already exists
 */
router.post(
  '/register',
  [
    body('name').trim().isLength({ min: 2, max: 100 }).withMessage('Name must be 2–100 characters'),
    body('email').isEmail().normalizeEmail().withMessage('Invalid email'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { name, email, password } = req.body;

      const existing = await User.findOne({ email });
      if (existing) {
        return res.status(400).json({ error: 'Email already registered' });
      }

      const user = await User.create({ name, email, password });

      const token = jwt.sign(
        { userId: user._id, email: user.email, role: user.role },
        process.env.JWT_SECRET || 'changeme',
        { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
      );

      res.status(201).json({
        message: 'User registered successfully',
        token,
        user,
      });
    } catch (err) {
      res.status(500).json({ error: 'Server error during registration' });
    }
  }
);

/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: Login with email and password
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, password]
 *             properties:
 *               email:
 *                 type: string
 *                 example: john@example.com
 *               password:
 *                 type: string
 *                 example: secret123
 *     responses:
 *       200:
 *         description: Login successful, returns JWT token
 *       401:
 *         description: Invalid credentials
 */
router.post(
  '/login',
  [
    body('email').isEmail().normalizeEmail().withMessage('Invalid email'),
    body('password').notEmpty().withMessage('Password is required'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      const { email, password } = req.body;

      const user = await User.findOne({ email }).select('+password');
      if (!user || !(await user.comparePassword(password))) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      if (!user.isActive) {
        return res.status(403).json({ error: 'Account is deactivated' });
      }

      const token = jwt.sign(
        { userId: user._id, email: user.email, role: user.role },
        process.env.JWT_SECRET || 'changeme',
        { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
      );

      res.json({
        message: 'Login successful',
        token,
        user: { id: user._id, name: user.name, email: user.email, role: user.role },
      });
    } catch (err) {
      res.status(500).json({ error: 'Server error during login' });
    }
  }
);

/**
 * @swagger
 * /auth/verify:
 *   get:
 *     summary: Verify a JWT token (used by other microservices)
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Token is valid, returns decoded user payload
 *       401:
 *         description: Token invalid or missing
 */
router.get('/verify', authenticate, (req, res) => {
  res.json({
    valid: true,
    user: req.user,
  });
});

/**
 * @swagger
 * /auth/profile:
 *   get:
 *     summary: Get current user profile
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: User profile data
 *       401:
 *         description: Unauthorized
 */
router.get('/profile', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

/**
 * @swagger
 * /auth/profile:
 *   put:
 *     summary: Update current user profile
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *     responses:
 *       200:
 *         description: Profile updated
 */
router.put(
  '/profile',
  authenticate,
  [body('name').optional().trim().isLength({ min: 2, max: 100 })],
  async (req, res) => {
    try {
      const updates = {};
      if (req.body.name) updates.name = req.body.name;

      const user = await User.findByIdAndUpdate(req.user.userId, updates, { new: true, runValidators: true });
      res.json({ message: 'Profile updated', user });
    } catch (err) {
      res.status(500).json({ error: 'Failed to update profile' });
    }
  }
);

module.exports = router;
