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

// General Rate Limiter for Public APIs (Anti-spam)
// Client polls location every 2s, so we need a generous limit.
// 2s = 30 req/min = 450 req/15min. We set limit to 1000 to be safe.
const publicApiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 1000,
    message: { message: "Too many requests, please chill." },
    standardHeaders: true,
    legacyHeaders: false,
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

// Global Active Admin Session (King of the Hill)
let activeAdminSessionId = null;

// Middleware to check if user is authenticated AND the current active admin
const isAuthenticated = (req, res, next) => {
    if (req.session && req.session.entryGranted) {
        // Valid session, but is it the *current* admin session?
        if (req.sessionID === activeAdminSessionId) {
            return next();
        }
        console.warn(`Blocked stale session attempt: ${req.sessionID} (Active: ${activeAdminSessionId})`);
    }
    return res.status(401).json({ message: 'Unauthorized or session overridden by new login' });
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

        // Take over the throne
        activeAdminSessionId = req.sessionID;
        console.log(`New Admin Login. Active Session ID set to: ${activeAdminSessionId}`);

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
app.get('/api/location', publicApiLimiter, (req, res) => {
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

// GET Snow Depth
app.get('/api/snow', publicApiLimiter, (req, res) => {
    // Cache for 1 hour to be nice to Skistar
    res.setHeader('Cache-Control', 'public, max-age=3600');

    // Check internal cache first (simple memory cache)
    const now = Date.now();
    if (global.snowCache && (now - global.snowCache.timestamp < 3600000)) {
        return res.json(global.snowCache.data);
    }

    const https = require('https');
    const url = "https://www.skistar.com/Lpv/SnowGraph?lang=sv&area=tandadalen";

    https.get(url, (externalRes) => {
        let data = '';

        externalRes.on('data', (chunk) => {
            data += chunk;
        });

        externalRes.on('end', () => {
            try {
                // Regex filtering for Tandådalen block
                // The structure is: <h5>Tandådalen</h5> ... <h5>VALUE cm</h5> ... 24H: ... VALUE cm ... 72H: ... VALUE cm

                // 1. Find the block starting with Tandådalen
                // Matches "Tand&#xE5;dalen" (HTML entity for å)
                const areaRegex = /Tand&#xE5;dalen[\s\S]*?(?=<h5 class="lpv-info-box__heading|$)/i;
                const areaMatch = data.match(areaRegex);

                if (!areaMatch) {
                    throw new Error("Could not find Tandådalen section");
                }

                const sectionHtml = areaMatch[0];

                // 2. Extract Depth
                // <span class="lpv-info-snow__value-number">41</span>
                const depthMatch = sectionHtml.match(/class="lpv-info-snow__value-number">\s*(\d+)\s*<\/span>/i);
                const depth = depthMatch ? depthMatch[1] : "?";

                // 3. Extract 24H
                // <span class="lpv-info-list__value">23 cm</span>
                const snow24hRegex = /24H:[\s\S]*?class="lpv-info-list__value">\s*(\d+)\s*cm/i;
                const match24 = sectionHtml.match(snow24hRegex);
                const snow24 = match24 ? match24[1] : "0";

                // 4. Extract 72H
                const snow72hRegex = /72H:[\s\S]*?class="lpv-info-list__value">\s*(\d+)\s*cm/i;
                const match72 = sectionHtml.match(snow72hRegex);
                const snow72 = match72 ? match72[1] : "0";

                const result = {
                    depth: depth,
                    snow24: snow24,
                    snow72: snow72
                };

                // Update cache
                global.snowCache = {
                    timestamp: now,
                    data: result
                };

                res.json(result);
            } catch (e) {
                console.error("Snow parse error:", e);
                // Return fallback or old cache if available
                if (global.snowCache) return res.json(global.snowCache.data);
                res.json({ depth: "?", snow24: "?", snow72: "?" });
            }
        });

    }).on("error", (err) => {
        console.error("Error fetching snow data:", err);
        res.status(500).json({ error: "Failed to fetch data" });
    });
});

// Helper Function: Fetch SMHI Forecast and Calculate Snow
const fetchSmhiSnowForecast = (lat, lon) => {
    return new Promise((resolve, reject) => {
        const https = require('https');
        // Point forecast (10 days)
        const url = `https://opendata-download-metfcst.smhi.se/api/category/pmp3g/version/2/geotype/point/lon/${lon}/lat/${lat}/data.json`;

        https.get(url, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    const forecast = JSON.parse(data);
                    const timeSeries = forecast.timeSeries;

                    let buckets = {
                        tomorrow: 0,
                        next5Days: 0,
                        next10Days: 0
                    };

                    const now = new Date();

                    // Define Tomorrow's Range (Calendar Day)
                    const tomorrowStart = new Date(now);
                    tomorrowStart.setDate(tomorrowStart.getDate() + 1);
                    tomorrowStart.setHours(0, 0, 0, 0);

                    const tomorrowEnd = new Date(tomorrowStart);
                    tomorrowEnd.setHours(23, 59, 59, 999);

                    // Define rolling windows
                    const fiveDaysEnd = new Date(now);
                    fiveDaysEnd.setDate(fiveDaysEnd.getDate() + 5);
                    fiveDaysEnd.setHours(23, 59, 59, 999); // Include full 5th day

                    const tenDaysEnd = new Date(now);
                    tenDaysEnd.setDate(tenDaysEnd.getDate() + 10);
                    tenDaysEnd.setHours(23, 59, 59, 999); // Include full 10th day

                    // Iterate and sum
                    for (let i = 0; i < timeSeries.length - 1; i++) {
                        const point = timeSeries[i];
                        const nextPoint = timeSeries[i + 1];

                        const validTime = new Date(point.validTime);

                        const nextTime = new Date(nextPoint.validTime).getTime();
                        const durationHours = (nextTime - validTime.getTime()) / (1000 * 3600);

                        // Find Parameters
                        const tParam = point.parameters.find(p => p.name === 't');
                        const pmeanParam = point.parameters.find(p => p.name === 'pmean');

                        if (!tParam || !pmeanParam) continue;

                        const temp = tParam.values[0];
                        const pmean = pmeanParam.values[0]; // mm/h

                        // STRICTLY use User's Temperature Rules for Snow Ratio
                        // Use 'pmean' which accounts for probability.
                        if (pmean > 0) {
                            let ratio = 0;

                            // +1°C to 0°C -> 1:5
                            if (temp <= 1 && temp >= 0) ratio = 5;
                            // -1°C to -3°C -> 1:10
                            else if (temp < 0 && temp >= -3) ratio = 10;
                            // -4°C to -10°C -> 1:15
                            else if (temp < -3 && temp >= -10) ratio = 15;
                            // < -10°C -> 1:20
                            else if (temp < -10) ratio = 20;

                            if (ratio > 0) {
                                const precipMm = pmean * durationHours;
                                const snowMm = precipMm * ratio;
                                const snowCm = snowMm / 10;

                                // Add to buckets

                                // Tomorrow
                                if (validTime >= tomorrowStart && validTime <= tomorrowEnd) {
                                    buckets.tomorrow += snowCm;
                                }

                                // Next 5 Days (from now)
                                if (validTime <= fiveDaysEnd) {
                                    buckets.next5Days += snowCm;
                                }

                                // Next 10 Days (from now, implicitly includes 5 days)
                                if (validTime <= tenDaysEnd) {
                                    buckets.next10Days += snowCm;
                                }
                            }
                        }
                    }

                    resolve(buckets);
                } catch (e) {
                    reject(e);
                }
            });
        }).on('error', (err) => reject(err));
    });
};

// GET Forecast Snow
app.get('/api/snow-forecast', publicApiLimiter, async (req, res) => {
    // Simple memory cache for 30 mins
    const now = Date.now();
    if (global.smhiSnowCache && (now - global.smhiSnowCache.timestamp < 1800000)) {
        return res.json(global.smhiSnowCache.data);
    }

    try {
        // Tandådalen coords
        const snowBuckets = await fetchSmhiSnowForecast('61.173735', '13.007344');

        // Format response
        const responseData = {
            location: "Tandådalen",
            forecast: {
                tomorrow: parseFloat(snowBuckets.tomorrow.toFixed(1)),
                next5Days: parseFloat(snowBuckets.next5Days.toFixed(1)),
                next10Days: parseFloat(snowBuckets.next10Days.toFixed(1))
            },
            until: "10 days"
        };

        global.smhiSnowCache = {
            timestamp: now,
            data: responseData
        };

        res.json(responseData);
    } catch (e) {
        console.error("SMHI Fetch Error", e);
        res.status(500).json({ error: "Could not fetch forecast" });
    }
});

// GET High Scores
app.get('/api/highscores', publicApiLimiter, (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
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
// Game is frame-rate bound. High refresh rate monitors (144hz, 240hz) run the game faster.
// 20 pts/sec is for 60hz. We need to allow much higher density for fast monitors.
const MAX_POINTS_PER_SEC = 100;

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
    res.setHeader('Cache-Control', 'no-store');
    const sessionId = crypto.randomBytes(16).toString('hex');
    const timestamp = Date.now();

    // Store session
    activeSessions.set(sessionId, {
        startTime: timestamp,
        ip: req.ip,
        heartbeats: 0,
        lastHeartbeat: timestamp
    });

    // Create signature of the sessionId
    const signature = crypto.createHmac('sha256', GAME_SECRET)
        .update(sessionId)
        .digest('hex');

    res.json({ sessionId, signature });
});

// POST Game Heartbeat
app.post('/api/game/heartbeat', (req, res) => {
    const { sessionId, signature } = req.body;
    if (!sessionId || !signature) return res.sendStatus(400);

    const session = activeSessions.get(sessionId);
    if (!session) return res.sendStatus(403);

    // Verify signature
    const expectedSignature = crypto.createHmac('sha256', GAME_SECRET)
        .update(sessionId)
        .digest('hex');
    if (signature !== expectedSignature) return res.sendStatus(403);

    // Update heartbeats
    session.heartbeats += 1;
    session.lastHeartbeat = Date.now();
    res.sendStatus(200);
});

// POST High Score
app.post('/api/highscore', (req, res) => {
    const { name, score, date, sessionId, signature } = req.body;

    // --- 0. STRICT INPUT SANITIZATION ---

    // Check 1: Score must be a non-negative integer
    // We allow 0. We reject strings that aren't clean numbers.
    if (typeof score !== 'number' || !Number.isInteger(score) || score < 0) {
        console.warn(`Invalid score format from IP ${req.ip}:`, score);
        return res.status(400).json({ message: "Invalid score format" });
    }

    // Check 2: Name must be a string and match whitelist (Letters, Numbers, Space, - _)
    // This blocks HTML, Script tags, Binary data, etc.
    if (typeof name !== 'string' || !/^[a-zA-Z0-9åäöÅÄÖ\s\-_]{1,20}$/.test(name)) {
        console.warn(`Invalid name format from IP ${req.ip}:`, name);
        return res.status(400).json({ message: "Invalid name (Endast bokstäver/siffror)" });
    }

    // 1. Verify Session Presence & Signature
    if (!sessionId || !signature) {
        return res.status(403).json({ message: "Missing game session" });
    }

    // Check if session exists in memory (One-Time Token logic)
    const session = activeSessions.get(sessionId);
    if (!session) {
        // Session not found (expired, invalid, or ALREADY USED)
        // Only warn here, don't ban immediately as it could be a race condition/network issue for legit users
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

    // 2. Verify Time/Score Feasibility (HEARTBEAT BASED)
    const HEARTBEAT_INTERVAL_SEC = 5;
    // Formula: (hb * 5) + 30. Generous buffer to account for lag/missed pings.
    // Allows ~30s of play (approx 400-600 pts) without heartbeats.
    const creditedDuration = (session.heartbeats * HEARTBEAT_INTERVAL_SEC) + 30;

    // Consume session IMMEDIATELY to prevent replay
    activeSessions.delete(sessionId);

    // Wall Clock Check (Physical Upper Bound)
    const wallClockDuration = (Date.now() - session.startTime) / 1000;
    if (wallClockDuration < 0) {
        return res.status(403).json({ message: "Time travel detected" });
    }

    // Valid is min of Heartbeat Credit AND Wall Clock (+2s buffer)
    const validDuration = Math.min(wallClockDuration + 2, creditedDuration);

    // Example calculation: MAX_POINTS_PER_SEC * duration. 
    const maxPossible = Math.ceil(validDuration * MAX_POINTS_PER_SEC);

    if (score > maxPossible) {
        console.warn(`Impossible score attempt (Heartbeat Check): ${score} points > ${maxPossible} max`);
        return res.status(403).json({ message: "Score validation failed (Keep tab active!)" });
    }

    // 3. Verify Score Granularity (Must be multiple of 10)
    // 3. Verify Score Granularity (Must be multiple of 10)
    if (score % 10 !== 0) {
        console.warn(`Invalid score value (not multiple of 10): ${score}`);
        return res.status(403).json({ message: "Invalid score value" });
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
