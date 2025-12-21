const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors'); // Kept for now, but configured or removed if not needed? Plan said remove or restrict. detailed plan said remove/restrict.
// Since it's served from same origin, we might not need it, or we can restrict it. 
// I'll keep it but restrict to same origin or just standard. 
// Actually, if it's served statically from the same server, we don't strictly need CORS for the frontend itself.
const path = require('path');
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
let currentLocation = {
    address: "Tandådalen",
    city: "Sälen",
    mapLink: "https://maps.google.com/maps?q=61.173735,13.007344&z=15&output=embed&t=k"
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
    res.json(currentLocation);
});

// POST location (Protected)
app.post('/api/location', isAuthenticated, (req, res) => {
    const { mapLink } = req.body;

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

                currentLocation.mapLink = finalLink;
                console.log("Map Link processed:", mapLink, "->", currentLocation.mapLink);
                return res.json({ message: "Link updated successfully", data: currentLocation });
            }
        } catch (e) {
            // Invalid URL
        }
    }

    res.status(400).json({ message: "Invalid URL provided" });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running at http://localhost:${PORT}`);
    console.log(`To access from phone use: http://YOUR_IP_ADDRESS:${PORT}/admin.html`);
});
