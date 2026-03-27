const express = require('express');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const User = require('../models/User');
const {signAccess, signRefresh, verifyRefresh} = require('../utils/jwt');

const router = express.Router();
const SALT_ROUNDS = 12;

function cookieOptions(isRefresh = false) {
    const isProd = process.env.NODE_ENV === 'production';
    const base = {
        httpOnly: true,
        secure: isProd,                 // true in prod (HTTPS), false for localhost http
        sameSite: isProd ? 'none' : 'lax',
        path: '/',                      // be consistent for set/clear
    };
    if (process.env.COOKIE_DOMAIN) base.domain = process.env.COOKIE_DOMAIN;
    if (!isRefresh) base.maxAge = 15 * 60 * 1000;         // 15 minutes
    else base.maxAge = 7 * 24 * 60 * 60 * 1000;           // 7 days
    return base;
}

// Throttle login attempts
const loginLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
});

// Signup
router.post('/signup', async (req, res, next) => {
    try {
        const {name, username, email, password} = req.body;
        if (!name || !username || !email || !password)
            return res.status(400).json({error: 'All fields are required'});

        const exists = await User.findOne({$or: [{email}, {username}]});
        if (exists) return res.status(409).json({error: 'User already exists'});

        const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
        const user = await User.create({name, username, email, passwordHash});

        // Create tokens
        const payload = {sub: user._id.toString(), username: user.username};
        const accessToken = signAccess(payload);
        const refreshToken = signRefresh(payload);

        // Set cookies
        res.cookie('accessToken', accessToken, cookieOptions(false));
        res.cookie('refreshToken', refreshToken, cookieOptions(true));

        // Return minimal public profile; no token in body
        res.status(201).json({
            id: user._id,
            name: user.name,
            username: user.username,
            email: user.email,
        });
    } catch (err) {
        // Handle duplicate key nicely
        if (err?.code === 11000) {
            return res.status(409).json({error: 'Email or username already taken'});
        }
        next(err);
    }
});

// Login
router.post('/login', loginLimiter, async (req, res, next) => {
    try {
        const {emailOrUsername, password} = req.body;
        if (!emailOrUsername || !password)
            return res.status(400).json({error: 'All input is required'});

        const user = await User.findOne({
            $or: [{email: emailOrUsername}, {username: emailOrUsername}],
        });
        if (!user) return res.status(404).json({error: 'Invalid credentials'});

        const ok = await bcrypt.compare(password, user.passwordHash);
        if (!ok) return res.status(404).json({error: 'Invalid credentials'});

        const payload = {sub: user._id.toString(), username: user.username};
        const accessToken = signAccess(payload);
        const refreshToken = signRefresh(payload);

        res.cookie('accessToken', accessToken, cookieOptions(false));
        res.cookie('refreshToken', refreshToken, cookieOptions(true));

        res.json({success: true});
    } catch (err) {
        next(err);
    }
});

// Refresh (rotate)
router.post('/refresh', async (req, res) => {
    const token = req.cookies?.refreshToken;
    if (!token) return res.status(401).json({error: 'Missing refresh token'});
    try {
        const payload = verifyRefresh(token);

        // Optional: check token against a token store / rotation list
        const newAccess = signAccess({sub: payload.sub, username: payload.username});
        const newRefresh = signRefresh({sub: payload.sub, username: payload.username});

        res.cookie('accessToken', newAccess, cookieOptions(false));
        res.cookie('refreshToken', newRefresh, cookieOptions(true));

        res.json({success: true});
    } catch {
        return res.status(401).json({error: 'Invalid refresh token'});
    }
});

// Logout
router.post('/logout', (req, res) => {
    const base = cookieOptions(false);
    const baseRefresh = cookieOptions(true);
    res.clearCookie('accessToken', base);
    res.clearCookie('refreshToken', baseRefresh);
    res.json({success: true});
});

// Example protected route
router.get('/me', require('../middleware/requireAuth'), async (req, res) => {
    // req.user set in requireAuth
    res.json({userId: req.user.sub, username: req.user.username});
});

module.exports = router;
