const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const path = require('path');
const User = require('./model'); // Ensure this path is correct
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const signalingServer = new WebSocket.Server({ port: 9090 }); // Signaling server for WebRTC

app.use(bodyParser.json());

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('MongoDB connected'))
  .catch((err) => console.log('MongoDB connection error:', err));

// Serve static files (including login.html, register.html, chat.html, admin.html)
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'landing.html'));
});


// Serve the login page
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Serve the register page
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// Serve the chat page
app.get('/chat', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'chat.html'));
});

// Serve the admin page
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// User Registration Route

// Example register route to hash password
app.post('/register', async (req, res) => {
    try {
        const { email, password, username } = req.body;

        if (!email || !password || !username) {
            return res.status(400).json({ message: 'Email, password, and username are required' });
        }

        const existingUser = await User.findOne({ email });

        if (existingUser) {
            return res.status(400).json({ message: 'User already exists with this email' });
        }

        // Hash password before saving it to the database
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const newUser = new User({
            email,
            password: hashedPassword, // Store hashed password
            username,
            role: 'user' // Default role (can be modified based on your logic)
        });

        await newUser.save();

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Server error during registration' });
    }
});



app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Check if email and password are provided
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        // Find the user by email
        const user = await User.findOne({ email });

        // If user doesn't exist, return an error
        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        // Compare the plain-text password with the hashed password in the database
        const isMatch = await bcrypt.compare(password, user.password);

        // If passwords do not match, return an error
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        // Generate JWT token for the authenticated user
        const token = jwt.sign(
            { id: user._id, username: user.username, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        // Send the token and user info as response
        res.json({ username: user.username, role: user.role, token });
    } catch (error) {
        res.status(500).json({ message: 'Server error during login' });
    }
});

// WebSocket Middleware to verify JWT token
// WebSocket Middleware to verify JWT token
wss.on('connection', (socket, req) => {
    const token = new URL(req.url, `http://${req.headers.host}`).searchParams.get('token');

    if (token) {
        // Handle authenticated users
        jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
            if (err) {
                socket.close();
                console.log('Connection denied: Invalid token');
                return;
            }

            console.log(`User ${decoded.username} connected`);

            // Handle incoming messages
            socket.on('message', (message) => {
                console.log(`Message from ${decoded.username}: ${message}`);

                // Broadcast message to all connected clients
                wss.clients.forEach((client) => {
                    if (client.readyState === WebSocket.OPEN) {
                        client.send(`${decoded.username}: ${message}`);
                    }
                });
            });

            socket.on('close', () => {
                console.log(`User ${decoded.username} disconnected`);
            });
        });
    } else {
        // Handle unauthenticated users
        console.log('Unauthenticated user connected');

        // Handle incoming messages from unauthenticated users (optional)
        socket.on('message', (message) => {
            console.log(`Message from unauthenticated user: ${message}`);

            // Broadcast message to all connected clients
            wss.clients.forEach((client) => {
                if (client.readyState === WebSocket.OPEN) {
                    client.send(` ${message}`);
                }
            });
        });

        socket.on('close', () => {
            console.log('Unauthenticated user disconnected');
        });
    }
});

// Admin Broadcast Route
app.post('/broadcast', async (req, res) => {
    try {
        const { message } = req.body;

        if (!message) {
            return res.status(400).json({ message: 'Message is required' });
        }

        // Broadcast message to all WebSocket clients
        wss.clients.forEach((client) => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(`Broadcast: ${message}`);
            }
        });

        res.json({ message: 'Broadcast message sent' });
    } catch (error) {
        console.error('Error during broadcast:', error);
        res.status(500).json({ message: 'Server error during broadcast' });
    }
});

// WebRTC Signaling Server
signalingServer.on('connection', (ws) => {
    ws.on('message', (message) => {
        signalingServer.clients.forEach((client) => {
            if (client !== ws && client.readyState === WebSocket.OPEN) {
                client.send(message);
            }
        });
    });
});

// Streaming endpoint
app.get('/stream', (req, res) => {
    const { streamId } = req.query;

    if (!streamId) {
        return res.status(400).send('Stream ID is required');
    }

    // Serve a placeholder message or implement actual streaming logic
    res.send(`Stream endpoint for streamId ${streamId}. Implement actual streaming logic here.`);
});

// Start the server
server.listen(8080, () => {
    console.log('Server is listening on port 8080');
});
