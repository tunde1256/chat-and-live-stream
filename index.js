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

// Use environment variable for port, fallback to 8080 for local development
const PORT = process.env.PORT || 8080;
const WS_PORT = process.env.WS_PORT || 9090; // WebSocket signaling server port

// WebSocket server for general communication
const wss = new WebSocket.Server({ server });

// WebSocket signaling server for WebRTC
const signalingServer = new WebSocket.Server({ port: WS_PORT });

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

        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const newUser = new User({
            email,
            password: hashedPassword,
            username,
            role: 'user'
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

        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        const user = await User.findOne({ email });

        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        const token = jwt.sign(
            { id: user._id, username: user.username, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({ username: user.username, role: user.role, token });
    } catch (error) {
        res.status(500).json({ message: 'Server error during login' });
    }
});

// WebSocket Middleware to verify JWT token
wss.on('connection', (socket, req) => {
    const token = new URL(req.url, `http://${req.headers.host}`).searchParams.get('token');

    if (token) {
        jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
            if (err) {
                socket.close();
                console.log('Connection denied: Invalid token');
                return;
            }

            console.log(`User ${decoded.username} connected`);

            socket.on('message', (message) => {
                console.log(`Message from ${decoded.username}: ${message}`);

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
        console.log('Unauthenticated user connected');

        socket.on('message', (message) => {
            console.log(`Message from unauthenticated user: ${message}`);

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

        wss.clients.forEach((client) => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(`Broadcast: ${message}`);
            }
        });

        res.json({ message: 'Broadcast message sent' });
    } catch (error) {
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

    res.send(`Stream endpoint for streamId ${streamId}. Implement actual streaming logic here.`);
});

// Start the server
server.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`);
});
