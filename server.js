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
        },
    },
}));

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
    mapLink: "https://www.google.com/maps/place/61%C2%B010'25.5%22N+13%C2%B000'26.4%22E/@61.1739025,13.0115595,749m/data=!3m1!1e3!4m4!3m3!8m2!3d61.173735!4d13.007344?entry=ttu&g_ep=EgoyMDI1MTIwOS4wIKXMDSoASAFQAw%3D%3D"
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
app.post('/api/login', (req, res) => {
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
                currentLocation.mapLink = mapLink;
                console.log("Map Link updated to:", currentLocation.mapLink);
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
