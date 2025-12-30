const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors'); // Kept for now, but configured or removed if not needed? Plan said remove or restrict. detailed plan said remove/restrict.
// Since it's served from same origin, we might not need it, or we can restrict it. 
// I'll keep it but restrict to same origin or just standard. 
// Actually, if it's served statically from the same server, we don't strictly need CORS for the frontend itself.
const path = require('path');
const fs = require('fs');
const HIGH_SCORES_FILE = path.join(__dirname, 'highscores.json');
require('dotenv').config();
const helmet = require('helmet');
const session = require('express-session');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// Security Middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "cdn.tailwindcss.com", "unpkg.com"],
            scriptSrcAttr: ["'unsafe-inline'"], // Allow inline event handlers
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            frameSrc: ["'self'", "https://*.google.com", "https://*.google.se"],
        },
    },
}));

// Rate Limiter for Login
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 requests per windowMs
    message: { message: "Too many login attempts, please try again later." },
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// Session Middleware
app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback_secret_do_not_use',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, // Set to true if using HTTPS
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Body Parser
app.use(bodyParser.json());

// Serve static files
app.use(express.static(path.join(__dirname, '/')));

// In-memory storage
let eventData = {
    address: "Tandådalen",
    city: "Sälen",
    mapLink: "https://maps.google.com/maps?q=61.173735,13.007344&z=15&output=embed&t=k",
    startTime: "12:00"
};

// Middleware to check if user is authenticated
const isAuthenticated = (req, res, next) => {
    if (req.session && req.session.entryGranted) {
        return next();
    }
    return res.status(401).json({ message: 'Unauthorized' });
};

// --- ROUTES ---

// Login Endpoint
app.post('/api/login', loginLimiter, (req, res) => {
    const { username, password } = req.body;

    // Simple check - in production use hashed passwords!
    // Plan assumes simple password check against env var for now as per "hazehaze"
    const adminUser = 'haze';
    const adminPass = process.env.ADMIN_PASSWORD;

    if (username && username.toLowerCase() === adminUser && password === adminPass) {
        req.session.entryGranted = true;
        return res.json({ message: 'Login successful' });
    }

    return res.status(401).json({ message: 'Invalid credentials' });
});

// Logout Endpoint
app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ message: 'Logged out' });
});

// GET location (Public)
app.get('/api/location', (req, res) => {
    res.setHeader('Cache-Control', 'no-cache');
    res.json(eventData);
});

// POST location (Protected)
app.post('/api/location', isAuthenticated, (req, res) => {
    const { mapLink, startTime } = req.body;

    // Update Time if provided
    if (startTime) {
        eventData.startTime = startTime;
    }

    // Update Map Link if provided
    if (mapLink) {
        // Basic input validation/sanitization
        // Ensure it looks like a URL
        try {
            const url = new URL(mapLink);
            if (url.protocol === 'http:' || url.protocol === 'https:') {
                let finalLink = mapLink;

                // Auto-convert standard Google Maps links to Embed links
                // Check if it's a google maps link (any TLD)
                if (mapLink.includes('google.') && mapLink.includes('/maps')) {
                    // Decode in case characters like @ are encoded
                    const decodedLink = decodeURIComponent(mapLink);
                    console.log("Processing Map Link:", decodedLink);

                    // Try to find coordinates @lat,lon
                    const coordMatch = decodedLink.match(/@(-?\d+(?:\.\d+)?),(-?\d+(?:\.\d+)?)/);
                    if (coordMatch) {
                        const [_, lat, lon] = coordMatch;
                        console.log("Found coordinates:", lat, lon);
                        finalLink = `https://maps.google.com/maps?q=${lat},${lon}&z=15&output=embed&t=k`;
                    } else {
                        // Try to find place name
                        const placeMatch = decodedLink.match(/\/maps\/place\/([^/]+)/);
                        if (placeMatch && placeMatch[1]) {
                            // Extract pretty name or encoded string
                            console.log("Found place:", placeMatch[1]);
                            finalLink = `https://maps.google.com/maps?q=${placeMatch[1]}&z=15&output=embed&t=k`;
                        } else if (!mapLink.includes('output=embed')) {
                            // If it's a search link like maps?q=... just append output=embed
                            if (mapLink.includes('?q=')) {
                                finalLink = mapLink + '&output=embed&t=k';
                            }
                        } else if (mapLink.includes('output=embed') && !mapLink.includes('&t=')) {
                            // If it is already an embed link but misses satellite view
                            finalLink = mapLink + '&t=k';
                        }
                    }
                }

                eventData.mapLink = finalLink;
                console.log("Map Link processed:", mapLink, "->", eventData.mapLink);
            }
        } catch (e) {
            // Invalid URL
        }
    }

    return res.json({ message: "Data updated successfully", data: eventData });
});

// GET High Scores
app.get('/api/highscores', (req, res) => {
    fs.readFile(HIGH_SCORES_FILE, 'utf8', (err, data) => {
        if (err) {
            // If file doesn't exist, return empty array
            if (err.code === 'ENOENT') {
                return res.json([]);
            }
            console.error("Error reading high scores:", err);
            return res.status(500).json({ message: "Error reading high scores" });
        }
        try {
            let scores = JSON.parse(data);
            // On read, ensure they have IDs too just in case
            let changed = false;
            scores = scores.map(s => {
                if (!s.id) {
                    s.id = Date.now().toString(36) + Math.random().toString(36).substr(2);
                    changed = true;
                }
                return s;
            });

            if (changed) {
                fs.writeFile(HIGH_SCORES_FILE, JSON.stringify(scores, null, 2), () => { });
            }

            res.json(scores);
        } catch (parseErr) {
            console.error("Error parsing high scores:", parseErr);
            res.json([]);
        }
    });
});

const crypto = require('crypto');
const GAME_SECRET = process.env.GAME_SECRET || 'dev_secret_key_change_in_prod';
const MAX_POINTS_PER_SEC = 20; // Reasonable limit based on game mechanics

// Active Game Sessions (Memory Store)
// Map<sessionId, { startTime: number, ip: string }>
const activeSessions = new Map();

// Cleanup old sessions every hour
setInterval(() => {
    const now = Date.now();
    for (const [id, session] of activeSessions.entries()) {
        if (now - session.startTime > 3600000) { // 1 hour expiration
            activeSessions.delete(id);
        }
    }
}, 3600000);


// GET Start Game Token
app.get('/api/game/start', (req, res) => {
    const sessionId = crypto.randomBytes(16).toString('hex');
    const timestamp = Date.now();

    // Store session
    activeSessions.set(sessionId, {
        startTime: timestamp,
        ip: req.ip
    });

    // Create signature of the sessionId to ensure we issued it (extra layer, though map check is cleaner)
    const signature = crypto.createHmac('sha256', GAME_SECRET)
        .update(sessionId)
        .digest('hex');

    res.json({ sessionId, signature });
});

// POST High Score
app.post('/api/highscore', (req, res) => {
    const { name, score, date, sessionId, signature } = req.body;

    if (!name || score === undefined) {
        return res.status(400).json({ message: "Invalid score data" });
    }

    // 1. Verify Session Presence & Signature
    if (!sessionId || !signature) {
        return res.status(403).json({ message: "Missing game session" });
    }

    // Check if session exists in memory (One-Time Token logic)
    const session = activeSessions.get(sessionId);
    if (!session) {
        // Session not found (expired, invalid, or ALREADY USED)
        console.warn(`Invalid or reused session attempt from IP: ${req.ip}`);
        return res.status(403).json({ message: "Invalid or expired game session" });
    }

    // Verify signature matches sessionId
    const expectedSignature = crypto.createHmac('sha256', GAME_SECRET)
        .update(sessionId)
        .digest('hex');

    if (signature !== expectedSignature) {
        return res.status(403).json({ message: "Invalid token signature" });
    }

    // 2. Verify Time/Score Feasibility
    const now = Date.now();
    // Use TRUSTED server-side start time
    const durationSeconds = (now - session.startTime) / 1000;

    // Consume session IMMEDIATELY to prevent replay
    activeSessions.delete(sessionId);

    // We expect at least minimal duration for any points.
    if (durationSeconds < 0) {
        return res.status(403).json({ message: "Time travel detected" });
    }

    // Example calculation: MAX_POINTS_PER_SEC * duration. 
    // + buffer for safety.
    const maxPossible = Math.ceil((durationSeconds + 2) * MAX_POINTS_PER_SEC);

    if (score > maxPossible) {
        console.warn(`Impossible score attempt: ${score} points in ${durationSeconds.toFixed(1)}s`);
        return res.status(403).json({ message: "Score validation failed" });
    }

    const newScore = {
        id: Date.now().toString(36) + Math.random().toString(36).substr(2),
        // Sanitize name a bit more?
        name: name.substring(0, 20), // Max length enforce
        score: parseInt(score),
        date: date || new Date().toLocaleDateString()
    };

    fs.readFile(HIGH_SCORES_FILE, 'utf8', (err, data) => {
        let scores = [];
        if (!err) {
            try {
                scores = JSON.parse(data);
                // Ensure existing scores have IDs (migration)
                scores = scores.map(s => {
                    if (!s.id) s.id = Date.now().toString(36) + Math.random().toString(36).substr(2);
                    return s;
                });
            } catch (e) {
                console.error("Error parsing high scores file, resetting:", e);
                scores = [];
            }
        }

        scores.push(newScore);
        // Sort descending
        scores.sort((a, b) => b.score - a.score);
        // Keep top 5
        scores = scores.slice(0, 5);

        // Keep IDs if we slice? Yes, because we slice the sorted array.

        fs.writeFile(HIGH_SCORES_FILE, JSON.stringify(scores, null, 2), (writeErr) => {
            if (writeErr) {
                console.error("Error writing high scores:", writeErr);
                return res.status(500).json({ message: "Failed to save score" });
            }
            res.json(scores);
        });
    });
});

// DELETE High Score (Protected)
app.delete('/api/highscore/:id', isAuthenticated, (req, res) => {
    const { id } = req.params;

    fs.readFile(HIGH_SCORES_FILE, 'utf8', (err, data) => {
        if (err) {
            return res.status(500).json({ message: "Error reading high scores" });
        }

        try {
            let scores = JSON.parse(data);
            const initialLength = scores.length;
            scores = scores.filter(s => s.id !== id);

            if (scores.length === initialLength) {
                return res.status(404).json({ message: "Score not found" });
            }

            fs.writeFile(HIGH_SCORES_FILE, JSON.stringify(scores, null, 2), (writeErr) => {
                if (writeErr) {
                    return res.status(500).json({ message: "Failed to save high scores" });
                }
                res.json({ message: "Score deleted", scores });
            });
        } catch (e) {
            res.status(500).json({ message: "Error processing high scores" });
        }
    });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running at http://localhost:${PORT}`);
    console.log(`To access from phone use: http://YOUR_IP_ADDRESS:${PORT}/admin.html`);
});
