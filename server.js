const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, '/'))); // Serve static files (html, css, images)

// In-memory storage for location (default starting values)
let currentLocation = {
    // Address is constant as per user request
    address: "Tandådalen",
    city: "Sälen",
    mapLink: "https://www.google.com/maps/place/61%C2%B010'25.5%22N+13%C2%B000'26.4%22E/@61.1739025,13.0115595,749m/data=!3m1!1e3!4m4!3m3!8m2!3d61.173735!4d13.007344?entry=ttu&g_ep=EgoyMDI1MTIwOS4wIKXMDSoASAFQAw%3D%3D"
};

// GET endpoint to retrieve current location
app.get('/api/location', (req, res) => {
    res.setHeader('Cache-Control', 'no-cache');
    res.json(currentLocation);
});

// POST endpoint to update location
// Expected JSON body: { "mapLink": "..." }
app.post('/api/location', (req, res) => {
    const { mapLink } = req.body;

    // Only allow updating the mapLink
    if (mapLink) currentLocation.mapLink = mapLink.replace(/\s/g, '');

    console.log("Map Link updated to:", currentLocation.mapLink);
    res.json({ message: "Link updated successfully", data: currentLocation });
});

// Start server
// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running at http://localhost:${PORT}`);
    console.log(`To access from phone use: http://YOUR_IP_ADDRESS:${PORT}/admin.html`);
});
