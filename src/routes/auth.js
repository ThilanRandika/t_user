const express = require('express');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const { authenticate, requireAdmin } = require('../middleware/auth');

const router = express.Router();
const NOTIFICATION_SERVICE_URL = process.env.NOTIFICATION_SERVICE_URL || 'http://localhost:3004';
const ORDER_SERVICE_URL = process.env.ORDER_SERVICE_URL || 'http://localhost:3003';
const PRODUCT_SERVICE_URL = process.env.PRODUCT_SERVICE_URL || 'http://localhost:3002';


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

      // Fire-and-forget Welcome Email
      axios.post(`${NOTIFICATION_SERVICE_URL}/api/notifications/welcome`, {
        email: user.email,
        name: user.name
      }).catch(err => console.error("Welcome notification failed:", err.message));

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

      // Add this Fire-and-forget Login Alert
      axios.post(`${NOTIFICATION_SERVICE_URL}/api/notifications/login-alert`, {
        email: user.email
      }).catch(err => console.error("Login notification failed:", err.message));

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
      axios.post(`${NOTIFICATION_SERVICE_URL}/api/notifications/profile-update`, {
        email: user.email,
        name: user.name
      }).catch(err => console.error("Profile update notification failed:", err.message));
      res.json({ message: 'Profile updated', user });
    } catch (err) {
      res.status(500).json({ error: 'Failed to update profile' });
    }
  }
);

/**
 * @swagger
 * /auth/users:
 *   get:
 *     summary: Get all registered users (Admin only)
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of all users
 *       403:
 *         description: Admin access required
 */
router.get('/users', authenticate, requireAdmin, async (req, res) => {
  try {
    const users = await User.find({}).select('-password').sort({ createdAt: -1 });
    res.json({ users });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

/**
 * @swagger
 * /auth/profile/full:
 *   get:
 *     summary: Get aggregated user dashboard (Profile + Orders)
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Full user profile including order history
 */
router.get('/profile/full', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    let orderHistory = [];
    try {
      // Make outbound call to the order service, passing along the user's JWT
      const { data } = await axios.get(`${ORDER_SERVICE_URL}/orders`, {
        headers: { Authorization: req.headers.authorization }, // Forward the Bearer token
        timeout: 5000
      });
      orderHistory = data.orders || [];
    } catch (orderErr) {
      console.warn(`[Aggregator Warning] Could not fetch orders for user ${req.user.userId}: ${orderErr.message}`);
      // Graceful degradation: If order service is down, still return profile but with an error note
      orderHistory = { error: 'Temporarily unavailable' };
    }

    // Wishlist Hydration: Make outbound calls to product service
    let hydratedWishlist = [];
    if (user.wishlist && user.wishlist.length > 0) {
      try {
        const productPromises = user.wishlist.map(id => 
          axios.get(`${PRODUCT_SERVICE_URL}/products/${id}`, { timeout: 3000 })
            .then(pRes => pRes.data.product)
            .catch(err => null) // Ignore 404s for deleted products
        );
        const resolvedProducts = await Promise.all(productPromises);
        hydratedWishlist = resolvedProducts.filter(p => p !== null);
      } catch (err) {
        console.warn(`[Hydration Warning] Could not hydrate wishlist for user ${req.user.userId}: ${err.message}`);
      }
    }

    res.json({ 
      user,
      orders: orderHistory,
      wishlist: hydratedWishlist
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch aggregated profile' });
  }
});


/**
 * @swagger
 * /auth/users/{id}/deactivate:
 *   put:
 *     summary: Deactivate a user and anonymize their orders (Admin only)
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: User deactivated
 */
router.put('/users/:id/deactivate', authenticate, requireAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    user.isActive = false;
    await user.save();

    // Fire-and-forget: Sync with Order Service to anonymize data
    axios.put(`${ORDER_SERVICE_URL}/orders/user/${user._id}/anonymize`, {}, {
      headers: { Authorization: req.headers.authorization }
    }).catch(err => console.error("Order anonymization sync failed:", err.message));

    res.json({ message: 'User deactivated successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to deactivate user' });
  }
});

/**
 * @swagger
 * /auth/profile/wishlist:
 *   put:
 *     summary: Add or remove an item from the wishlist
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [productId, action]
 *             properties:
 *               productId:
 *                 type: string
 *               action:
 *                 type: string
 *                 enum: [add, remove]
 *     responses:
 *       200:
 *         description: Wishlist updated
 */
router.put(
  '/profile/wishlist',
  authenticate,
  [
    body('productId').trim().notEmpty().withMessage('Product ID is required'),
    body('action').isIn(['add', 'remove']).withMessage('Action must be add or remove'),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    try {
      const { productId, action } = req.body;
      const update = action === 'add' 
        ? { $addToSet: { wishlist: productId } }
        : { $pull: { wishlist: productId } };

      const user = await User.findByIdAndUpdate(req.user.userId, update, { new: true });
      res.json({ message: 'Wishlist updated', wishlist: user.wishlist });
    } catch (err) {
      res.status(500).json({ error: 'Failed to update wishlist' });
    }
  }
);

module.exports = router;
