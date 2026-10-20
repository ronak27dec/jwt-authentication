require('dotenv').config();

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('node:crypto');

const app = express();
app.use(express.json());
const users = new Map();

app.post('/auth/register', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (
            typeof email !== 'string' ||
            typeof password !== 'string' ||
            !email.trim() ||
            password.length < 12
        ) {
            return res.status(400).json({
                message:
                    'Valid email and a password of at least 12 characters are required',
            });
        }

        const normalizedEmail = email.trim().toLowerCase();

        if (users.has(normalizedEmail)) {
            return res.status(409).json({
                message: 'Unable to register with these details',
            });
        }

        // Never store a plaintext password.
        const passwordHash = await bcrypt.hash(password, 12);

        const user = {
            id: crypto.randomUUID(),
            email: normalizedEmail,
            passwordHash,
        };

        users.set(normalizedEmail, user);

        return res.status(201).json({
            message: 'Registration successful',
        });
    } catch (error) {
        return res.status(500).json({
            message: 'Internal server error',
        });
    }
});

app.post('/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (typeof email !== 'string' || typeof password !== 'string') {
            return res.status(400).json({
                message: 'Email and password are required',
            });
        }

        const normalizedEmail = email.trim().toLowerCase();
        const user = users.get(normalizedEmail);

        if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
            return res.status(401).json({
                message: 'Invalid email or password',
            });
        }

        const token = jwt.sign(
            {
                sub: user.id,
            },
            process.env.JWT_SECRET,
            {
                algorithm: 'HS256',
                expiresIn: process.env.JWT_EXPIRES_IN || '15m',
            }
        );

        return res.status(200).json({
            accessToken: token,
            tokenType: 'Bearer',
            expiresIn: 900,
        });
    } catch (error) {
        return res.status(500).json({
            message: 'Internal server error',
        });
    }
});

function authenticateToken(req, res, next) {
    const authorization = req.headers.authorization;
    if (!authorization) {
        return res.status(401).json({ message: 'Authentication Required' });
    }

    const [scheme, token, ...extra] = authorization.split(' ');
    if (scheme != 'Bearer' || !token || extra.length > 0) {
        res.status(401).json({ message: 'Invalid Authorization headers' });
    }

    try {
        const payload = jwt.verify(token, process.env.JWT_SECRET, {
            algorithms: ['HS256'],
        });

        req.auth = {
            userId: payload.sub,
        };

        next();
    } catch (error) {
        return res.status(401).json({ message: 'Invalid or expired token' });
    }
}

app.get('/profile', authenticateToken, (req, res) => {
    return res
        .status(200)
        .json({ userId: req.auth.userId, message: 'You are authentcated' });
});

app.listen(process.env.PORT || 3000, () => {
    console.log('Server running');
});
