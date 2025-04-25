const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*", methods: ["GET", "POST"] }
});
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-very-secret-key-in-production!';
const DB_FILE = path.join(__dirname, 'chat_app.db');
const HISTORY_LIMIT = 50;

let db;
try {
    db = new sqlite3.Database(DB_FILE, sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
        if (err) {
            console.error('SQLite DB Connection Error:', err.message);
            process.exit(1);
        }
        console.log(`SQLite DB Connected (${DB_FILE}).`);

        db.serialize(() => {
            db.run('PRAGMA foreign_keys = ON;', (err) => {
                 if (err) console.error("Foreign key pragma error:", err.message);
                 else console.log("Foreign key support enabled.");
            });

            db.run(`CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                profile_pic_path TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )`, (err) => {
                if (err) {
                    console.error("Error creating/checking 'users' table:", err.message);
                    process.exit(1);
                }
                 console.log("'users' table checked/created.");
            });

            db.run(`CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id TEXT NOT NULL,
                sender_id INTEGER NOT NULL,
                recipient_id INTEGER,
                text TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (recipient_id) REFERENCES users (id) ON DELETE SET NULL
            )`, (err) => {
                 if (err) console.error("Error creating/checking 'messages' table:", err.message);
                 else console.log("'messages' table checked/created.");
            });
        });
    });
} catch (error) {
    console.error("Critical error during database initialization:", error);
    process.exit(1);
}

function dbRun(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function (err) {
            if (err) reject(err);
            else resolve(this);
        });
    });
}
function dbGet(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}
function dbAll(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
}

const onlineUsers = new Map();
const userIdToSocketIdMap = new Map();

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(__dirname)); // Serve index.html, chat.html from root

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    console.log(`Creating directory: '${uploadsDir}'`);
    fs.mkdirSync(uploadsDir, { recursive: true });
}
const publicSoundsDir = path.join(__dirname, 'public', 'sounds');
if (!fs.existsSync(publicSoundsDir)) {
     console.log(`Creating directory: '${publicSoundsDir}'`);
    fs.mkdirSync(publicSoundsDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename: (req, file, cb) => cb(null, 'profilePic-' + Date.now() + path.extname(file.originalname))
});
const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const filetypes = /jpeg|jpg|png|gif/;
        const mimetype = filetypes.test(file.mimetype);
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
        if (mimetype && extname) {
            return cb(null, true);
        }
        cb(new Error("Error: Only image files are allowed (jpeg, jpg, png, gif)."));
    }
});

const getFullProfilePicUrl = (req, profilePicPath) => {
    if (!profilePicPath) return null;
    const proto = req ? req.protocol : (process.env.NODE_ENV === 'production' ? 'https' : 'http');
    // Determine host: Use request's host if available, else HOST env var, else fallback
    const host = req ? req.get('host') : (process.env.HOST || `localhost:${PORT}`);
    const fullPath = profilePicPath.startsWith('/uploads/') ? profilePicPath : `/uploads/${profilePicPath}`;
    try {
        // Construct URL carefully to avoid issues with // in path
        const baseUrl = `${proto}://${host}`;
        return new URL(fullPath, baseUrl).toString();
    } catch (e) {
        console.error("Error creating profile pic URL:", e, "using fallback.");
        return `${proto}://${host}${fullPath}`; // Fallback
    }
};


const getPrivateChatIdServer = (userId1, userId2) => {
    const id1 = parseInt(userId1);
    const id2 = parseInt(userId2);
    if (isNaN(id1) || isNaN(id2)) return null;
    const sortedIds = [id1, id2].sort((a, b) => a - b);
    return `private_${sortedIds[0]}_${sortedIds[1]}`;
};

app.post('/api/register', upload.single('profilePic'), async (req, res) => {
    const { username, email, password } = req.body;
    const profileFile = req.file;

    try {
        if (!username || !email || !password) {
            if (profileFile) { try { fs.unlinkSync(profileFile.path); } catch(e){ console.error("Error unlinking file on bad request:", e)} }
            return res.status(400).json({ message: 'Username, email, and password are required.' });
        }

        const existingUser = await dbGet('SELECT id FROM users WHERE email = ? OR username = ?', [email.toLowerCase(), username]);
        if (existingUser) {
            if (profileFile) { try { fs.unlinkSync(profileFile.path); } catch(e){ console.error("Error unlinking file on conflict:", e)} }
            return res.status(409).json({ message: 'Email or username already in use.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const profilePicDbPath = profileFile ? profileFile.filename : null;

        const result = await dbRun(
            'INSERT INTO users (username, email, password_hash, profile_pic_path) VALUES (?, ?, ?, ?)',
            [username, email.toLowerCase(), hashedPassword, profilePicDbPath]
        );
        const newUserId = result.lastID;
        console.log("New User Registered (SQLite):", { id: newUserId, username });

        const token = jwt.sign({ userId: newUserId, email: email.toLowerCase() }, JWT_SECRET, { expiresIn: '24h' });

        res.status(201).json({
            message: 'Registration successful!',
            token,
            user: {
                id: newUserId,
                username,
                email: email.toLowerCase(),
                profilePic: getFullProfilePicUrl(req, profilePicDbPath) // Use filename directly
            }
        });

    } catch (error) {
        console.error("Registration Error:", error);
        if (profileFile && profileFile.path) {
            try { fs.unlinkSync(profileFile.path); } catch (e) { console.error("Error unlinking file on registration error:", e); }
        }
        if (error instanceof multer.MulterError || error.message?.includes('Error: Only image files')) {
            return res.status(400).json({ message: error.message });
        }
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required.' });
        }

        const user = await dbGet('SELECT id, username, email, password_hash, profile_pic_path FROM users WHERE email = ?', [email.toLowerCase()]);
        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password.' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password_hash);
        if (!passwordMatch) {
            return res.status(401).json({ message: 'Invalid email or password.' });
        }

        const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
        console.log("User Logged In (SQLite):", { id: user.id, username: user.username });

        res.status(200).json({
            message: 'Login successful!',
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                profilePic: getFullProfilePicUrl(req, user.profile_pic_path) // Use filename directly
            }
        });

    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ message: 'Server error during login.' });
    }
});

const authenticateTokenHttp = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, payload) => {
        if (err) {
            console.log("JWT Verification Error (HTTP):", err.message);
            return res.status(403).json({ message: "Session invalid or expired." });
        }
        req.user = payload;
        next();
    });
};

app.get('/api/me', authenticateTokenHttp, async (req, res) => {
    const userId = req.user.userId;

    try {
        const user = await dbGet('SELECT id, username, email, profile_pic_path FROM users WHERE id = ?', [userId]);
        if (!user) {
            return res.status(404).json({ message: 'User not found.' });
        }
        console.log(`/api/me request successful (User: ${user.username}, ID: ${userId})`);
        res.status(200).json({
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                profilePic: getFullProfilePicUrl(req, user.profile_pic_path) // Use filename directly
            }
        });
    } catch (error) {
        console.error("/api/me Error:", error);
        res.status(500).json({ message: 'Server error fetching user profile.' });
    }
});

// Serve root HTML files
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});
app.get('/chat.html', (req, res) => {
     res.sendFile(path.join(__dirname, 'chat.html'));
});


const broadcastOnlineUsers = () => {
    const usersArray = Array.from(onlineUsers.values());
    io.emit('updateUserList', usersArray);
};

io.on('connection', (socket) => {
    console.log(`New Connection: ${socket.id}`);

    socket.on('authenticate', async (token) => {
        try {
            if (!token) throw new Error('Token missing');

            const decoded = jwt.verify(token, JWT_SECRET);
            const user = await dbGet('SELECT id, username, profile_pic_path FROM users WHERE id = ?', [decoded.userId]);
            if (!user) throw new Error('User not found in database');

            const userData = {
                id: user.id,
                username: user.username,
                profilePic: getFullProfilePicUrl(null, user.profile_pic_path) // No req here
            };

            const existingSocketId = userIdToSocketIdMap.get(user.id);
            if (existingSocketId && existingSocketId !== socket.id) {
                const oldSocket = io.sockets.sockets.get(existingSocketId);
                if (oldSocket) {
                     console.log(`Disconnecting old socket ${existingSocketId} for user ${user.username}.`);
                     oldSocket.disconnect(true);
                }
                onlineUsers.delete(existingSocketId);
            }

            socket.user = userData;
            onlineUsers.set(socket.id, userData);
            userIdToSocketIdMap.set(user.id, socket.id);

            console.log(`User Authenticated: ${userData.username} (Socket: ${socket.id}, UserID: ${userData.id})`);

            socket.emit('auth_success', userData);
            io.emit('serverMessage', `${userData.username} joined the chat.`);
            broadcastOnlineUsers();

        } catch (error) {
            console.error(`Authentication Error (${socket.id}):`, error.message);
            socket.emit('auth_failed');
            socket.disconnect(true);
        }
    });

    socket.on('chatMessage', async (msgText) => {
        if (!socket.user || typeof msgText !== 'string' || !msgText.trim()) return;

        const sanitizedMsg = msgText.trim();
        if (!sanitizedMsg) return;

        const chatId = 'general';
        console.log(`[${chatId}] ${socket.user.username}: ${sanitizedMsg.substring(0, 50)}...`);

        try {
            const result = await dbRun(
                'INSERT INTO messages (chat_id, sender_id, text) VALUES (?, ?, ?)',
                [chatId, socket.user.id, sanitizedMsg]
            );
            const messageId = result.lastID;

            const messageData = {
                id: messageId,
                chatId: chatId,
                text: sanitizedMsg,
                senderId: socket.user.id,
                senderName: socket.user.username,
                senderAvatar: socket.user.profilePic,
                timestamp: new Date(),
                isPrivate: false
            };

            io.emit('newChatMessage', messageData);

        } catch (dbError) {
            console.error(`[${chatId}] DB Error saving message:`, dbError);
            socket.emit('serverMessage', 'Error sending message.');
        }
    });

    socket.on('privateMessage', async (data) => {
        if (!socket.user || !data || !data.recipientId || typeof data.text !== 'string' || !data.text.trim()) {
            console.warn("Invalid private message data received:", data, "- Sender:", socket.user?.username);
            return;
        }

        const recipientId = parseInt(data.recipientId);
        const senderId = socket.user.id;
        const sanitizedMsg = data.text.trim();
        if (!sanitizedMsg) return;

        if (isNaN(recipientId) || recipientId === senderId) {
            console.warn("Invalid recipient ID or self-message:", recipientId, "- Sender:", socket.user.username);
            socket.emit('serverMessage', 'Cannot send message to this recipient.');
            return;
        }

        const chatId = getPrivateChatIdServer(senderId, recipientId);
        if (!chatId) {
             console.error("Could not generate private chat ID:", senderId, recipientId);
             socket.emit('serverMessage', 'Error sending message (chat ID).');
             return;
        }

        console.log(`[${chatId}] ${socket.user.username} -> Recipient ${recipientId}: ${sanitizedMsg.substring(0, 50)}...`);

        try {
            const result = await dbRun(
                'INSERT INTO messages (chat_id, sender_id, recipient_id, text) VALUES (?, ?, ?, ?)',
                [chatId, senderId, recipientId, sanitizedMsg]
            );
            const messageId = result.lastID;

            const messageData = {
                id: messageId,
                chatId: chatId,
                text: sanitizedMsg,
                senderId: senderId,
                senderName: socket.user.username,
                senderAvatar: socket.user.profilePic,
                recipientId: recipientId,
                timestamp: new Date(),
                isPrivate: true
            };

            const recipientSocketId = userIdToSocketIdMap.get(recipientId);

            if (recipientSocketId) {
                io.to(recipientSocketId).emit('newPrivateMessage', messageData);
                console.log(` -> Sent to recipient socket ${recipientSocketId}.`);
            } else {
                console.log(` -> Recipient (ID: ${recipientId}) is offline.`);
            }

            socket.emit('newPrivateMessage', messageData);

        } catch (dbError) {
            console.error(`[${chatId}] DB Error saving private message:`, dbError);
            socket.emit('serverMessage', 'Error saving message to database.');
        }
    });

    socket.on('requestHistory', async (data) => {
        if (!socket.user || !data || !data.chatId) {
            console.warn("Invalid history request:", data, "- Sender:", socket.user?.username);
            return;
        }
        const chatId = data.chatId;
        const userId = socket.user.id;

        console.log(`User ${userId} (${socket.user.username}) requested history for '${chatId}'.`);

        if (chatId.startsWith('private_')) {
            const ids = chatId.split('_');
            if (ids.length !== 3 || !ids.includes(String(userId))) {
                 console.warn(`Unauthorized history request: User ${userId} for chat ${chatId}.`);
                 socket.emit('chatHistory', { chatId, messages: [], error: "You don't have access to this chat." });
                 return;
            }
        }

        try {
            const query = `
                SELECT m.id, m.chat_id as chatId, m.sender_id as senderId, m.recipient_id as recipientId, m.text, m.timestamp,
                       u.username as senderName, u.profile_pic_path as senderAvatarPath
                FROM messages m
                JOIN users u ON m.sender_id = u.id
                WHERE m.chat_id = ?
                ORDER BY m.timestamp DESC
                LIMIT ?
            `;
            const rows = await dbAll(query, [chatId, HISTORY_LIMIT]);

            const messages = rows.reverse().map(row => ({
                id: row.id,
                chatId: row.chatId,
                senderId: row.senderId,
                recipientId: row.recipientId,
                text: row.text,
                timestamp: row.timestamp,
                senderName: row.senderName,
                senderAvatar: getFullProfilePicUrl(null, row.senderAvatarPath), // No req here
                isPrivate: chatId.startsWith('private_')
            }));

            console.log(`Sending ${messages.length} history messages for '${chatId}'.`);
            socket.emit('chatHistory', { chatId, messages });

        } catch (dbError) {
            console.error(`[${chatId}] DB Error loading history:`, dbError);
            socket.emit('chatHistory', { chatId, messages: [], error: "Error loading chat history." });
        }
    });


    socket.on('startTyping', (data) => {
        if (!socket.user || !data || !data.chatId) return;

        const chatId = data.chatId;
        const typerInfo = {
            userId: socket.user.id,
            username: socket.user.username,
            chatId: chatId
        };

        if (chatId === 'general') {
            socket.broadcast.emit('userTyping', typerInfo);
        } else if (chatId.startsWith('private_')) {
            const ids = chatId.split('_');
            const otherUserIdString = ids.find(id => id !== 'private' && parseInt(id) !== socket.user.id);
            const otherUserId = parseInt(otherUserIdString);

            if (!isNaN(otherUserId)) {
                const recipientSocketId = userIdToSocketIdMap.get(otherUserId);
                if (recipientSocketId) {
                    io.to(recipientSocketId).emit('userTyping', typerInfo);
                }
            }
        }
    });

    socket.on('stopTyping', (data) => {
        if (!socket.user || !data || !data.chatId) return;

        const chatId = data.chatId;
        const typerInfo = {
            userId: socket.user.id,
            chatId: chatId
        };

        if (chatId === 'general') {
            socket.broadcast.emit('userStoppedTyping', typerInfo);
        } else if (chatId.startsWith('private_')) {
            const ids = chatId.split('_');
            const otherUserIdString = ids.find(id => id !== 'private' && parseInt(id) !== socket.user.id);
            const otherUserId = parseInt(otherUserIdString);
            if (!isNaN(otherUserId)) {
                const recipientSocketId = userIdToSocketIdMap.get(otherUserId);
                if (recipientSocketId) {
                    io.to(recipientSocketId).emit('userStoppedTyping', typerInfo);
                }
            }
        }
    });

    socket.on('disconnect', (reason) => {
        console.log(`Connection Closed: ${socket.id}, Reason: ${reason}`);
        if (socket.user) {
            console.log(`${socket.user.username} (ID: ${socket.user.id}) disconnected.`);
            const userId = socket.user.id;
            onlineUsers.delete(socket.id);
            if (userIdToSocketIdMap.get(userId) === socket.id) {
                 userIdToSocketIdMap.delete(userId);
            }
            io.emit('serverMessage', `${socket.user.username} left the chat.`);
            broadcastOnlineUsers();

             io.emit('userStoppedTyping', { userId: userId, chatId: 'general' });
             // Consider adding logic here to notify relevant private chats too
        }
    });
});

server.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Database file: ${DB_FILE}`);
    console.log(`JWT Secret: ${JWT_SECRET.startsWith('change-this') ? 'Default (INSECURE!)' : 'Set'}`);
});

process.on('SIGINT', () => {
    console.log('\nSIGINT received. Shutting down gracefully...');
    io.close(() => {
        console.log("Socket.IO server closed.");
    });
    db.close((err) => {
        if (err) {
            console.error("Error closing DB:", err.message);
            process.exit(1);
        }
        console.log('SQLite database connection closed.');
        server.close(() => {
             console.log("HTTP server closed.");
             process.exit(0);
        });
        setTimeout(() => {
            console.error("Shutdown timed out, forcing exit.");
            process.exit(1);
        }, 2000);
    });
});