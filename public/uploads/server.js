// server.js - Main server file
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');
const xss = require('xss');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

// Environment variables (create a .env file)
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this';
const UPLOAD_PATH = process.env.UPLOAD_PATH || './uploads';

// Create uploads directory if it doesn't exist
if (!fs.existsSync(UPLOAD_PATH)) {
    fs.mkdirSync(UPLOAD_PATH, { recursive: true });
}

// Security middleware
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 auth attempts per windowMs
    message: 'Too many authentication attempts, please try again later.'
});

app.use(limiter);
app.use('/api/auth', authLimiter);

// Static file serving for uploads
app.use('/uploads', express.static(UPLOAD_PATH));

// In-memory storage (replace with MongoDB/PostgreSQL for production)
let users = [];
let messages = [];
let files = [];
let connectedUsers = new Map();

// File upload configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, UPLOAD_PATH);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const fileFilter = (req, file, cb) => {
    // Allowed file types
    const allowedTypes = /jpeg|jpg|png|gif|pdf|txt|doc|docx|xls|xlsx|zip|rar/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);

    if (mimetype && extname) {
        return cb(null, true);
    } else {
        cb(new Error('Invalid file type'));
    }
};

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 10 * 1024 * 1024 // 10MB limit
    },
    fileFilter: fileFilter
});

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
    const token = req.header('x-auth-token') || req.query.token;

    if (!token) {
        return res.status(401).json({ message: 'No token, access denied' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Token is not valid' });
    }
};

// Socket.io middleware for authentication
io.use((socket, next) => {
    const token = socket.handshake.auth.token;

    if (!token) {
        return next(new Error('Authentication error'));
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        socket.userId = decoded.id;
        socket.username = decoded.username;
        next();
    } catch (error) {
        next(new Error('Authentication error'));
    }
});

// Utility functions
const sanitizeInput = (input) => {
    return xss(validator.escape(input));
};

const findUserByEmail = (email) => {
    return users.find(user => user.email === email);
};

const findUserById = (id) => {
    return users.find(user => user.id === id);
};

// Authentication routes
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Input validation
        if (!username || !email || !password) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        if (!validator.isEmail(email)) {
            return res.status(400).json({ message: 'Invalid email format' });
        }

        if (password.length < 6) {
            return res.status(400).json({ message: 'Password must be at least 6 characters' });
        }

        // Sanitize inputs
        const cleanUsername = sanitizeInput(username);
        const cleanEmail = sanitizeInput(email.toLowerCase());

        // Check if user already exists
        if (findUserByEmail(cleanEmail)) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create user
        const user = {
            id: Date.now().toString(),
            username: cleanUsername,
            email: cleanEmail,
            password: hashedPassword,
            createdAt: new Date(),
            avatar: cleanUsername.charAt(0).toUpperCase()
        };

        users.push(user);

        // Create JWT token
        const token = jwt.sign(
            { id: user.id, username: user.username, email: user.email },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.status(201).json({
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                avatar: user.avatar
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Input validation
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        const cleanEmail = sanitizeInput(email.toLowerCase());

        // Find user
        const user = findUserByEmail(cleanEmail);
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Check password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Create JWT token
        const token = jwt.sign(
            { id: user.id, username: user.username, email: user.email },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                avatar: user.avatar
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Get current user
app.get('/api/auth/me', verifyToken, (req, res) => {
    const user = findUserById(req.user.id);
    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }

    res.json({
        user: {
            id: user.id,
            username: user.username,
            email: user.email,
            avatar: user.avatar
        }
    });
});

// Chat routes
app.get('/api/messages', verifyToken, (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const startIndex = (page - 1) * limit;
    const endIndex = startIndex + limit;

    const paginatedMessages = messages
        .slice(-limit * page)
        .slice(startIndex, endIndex)
        .map(msg => ({
            ...msg,
            text: sanitizeInput(msg.text)
        }));

    res.json({
        messages: paginatedMessages,
        hasMore: messages.length > page * limit
    });
});

// File routes
app.post('/api/files/upload', verifyToken, upload.single('file'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ message: 'No file uploaded' });
        }

        const fileObj = {
            id: Date.now().toString(),
            name: req.file.originalname,
            filename: req.file.filename,
            size: req.file.size,
            mimetype: req.file.mimetype,
            uploadedBy: req.user.id,
            uploadedAt: new Date(),
            path: `/uploads/${req.file.filename}`
        };

        files.push(fileObj);

        // Broadcast file upload to all connected users
        io.emit('fileUploaded', {
            file: fileObj,
            user: req.user
        });

        res.json({ file: fileObj });
    } catch (error) {
        console.error('File upload error:', error);
        res.status(500).json({ message: 'File upload failed' });
    }
});

app.get('/api/files', verifyToken, (req, res) => {
    const userFiles = files
        .filter(file => file.uploadedBy === req.user.id)
        .map(file => ({
            id: file.id,
            name: file.name,
            size: file.size,
            mimetype: file.mimetype,
            uploadedAt: file.uploadedAt,
            path: file.path
        }));

    res.json({ files: userFiles });
});

app.delete('/api/files/:fileId', verifyToken, (req, res) => {
    const fileId = req.params.fileId;
    const fileIndex = files.findIndex(f => f.id === fileId && f.uploadedBy === req.user.id);

    if (fileIndex === -1) {
        return res.status(404).json({ message: 'File not found' });
    }

    const file = files[fileIndex];

    // Delete physical file
    const filePath = path.join(UPLOAD_PATH, file.filename);
    if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
    }

    // Remove from array
    files.splice(fileIndex, 1);

    res.json({ message: 'File deleted successfully' });
});

// Socket.io connection handling
io.on('connection', (socket) => {
    console.log(`User ${socket.username} connected`);

    // Add user to connected users
    connectedUsers.set(socket.userId, {
        id: socket.userId,
        username: socket.username,
        socketId: socket.id
    });

    // Broadcast updated user list
    io.emit('usersUpdate', Array.from(connectedUsers.values()));

    // Handle new message
    socket.on('sendMessage', (data) => {
        try {
            const message = {
                id: Date.now().toString(),
                userId: socket.userId,
                username: socket.username,
                text: sanitizeInput(data.text),
                timestamp: new Date(),
                type: 'message'
            };

            messages.push(message);

            // Keep only last 1000 messages in memory
            if (messages.length > 1000) {
                messages.shift();
            }

            // Broadcast message to all connected clients
            io.emit('newMessage', message);
        } catch (error) {
            console.error('Message error:', error);
            socket.emit('error', { message: 'Failed to send message' });
        }
    });

    // Handle file share in chat
    socket.on('shareFile', (data) => {
        try {
            const file = files.find(f => f.id === data.fileId && f.uploadedBy === socket.userId);
            if (!file) {
                socket.emit('error', { message: 'File not found' });
                return;
            }

            const message = {
                id: Date.now().toString(),
                userId: socket.userId,
                username: socket.username,
                text: `📎 ${file.name}`,
                timestamp: new Date(),
                type: 'file',
                file: {
                    id: file.id,
                    name: file.name,
                    size: file.size,
                    path: file.path
                }
            };

            messages.push(message);
            io.emit('newMessage', message);
        } catch (error) {
            console.error('File share error:', error);
            socket.emit('error', { message: 'Failed to share file' });
        }
    });

    // Handle typing indicator
    socket.on('typing', (data) => {
        socket.broadcast.emit('userTyping', {
            userId: socket.userId,
            username: socket.username,
            isTyping: data.isTyping
        });
    });

    // Handle disconnect
    socket.on('disconnect', () => {
        console.log(`User ${socket.username} disconnected`);
        connectedUsers.delete(socket.userId);

        // Broadcast updated user list
        io.emit('usersUpdate', Array.from(connectedUsers.values()));
    });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        status: 'OK',
        timestamp: new Date(),
        users: users.length,
        messages: messages.length,
        files: files.length,
        connectedUsers: connectedUsers.size
    });
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Server error:', error);

    if (error.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ message: 'File too large' });
    }

    if (error.message === 'Invalid file type') {
        return res.status(400).json({ message: 'Invalid file type' });
    }

    res.status(500).json({ message: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ message: 'Route not found' });
});

server.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📁 Upload directory: ${UPLOAD_PATH}`);
    console.log(`🔐 JWT Secret: ${JWT_SECRET.substring(0, 10)}...`);
});

module.exports = app;