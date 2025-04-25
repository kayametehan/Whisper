
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
const JWT_SECRET = process.env.JWT_SECRET || 'cok-gizli-bir-jwt-anahtari-mutlaka-degistir!';
const DB_FILE = path.join(__dirname, 'chat_app.db'); 
const HISTORY_LIMIT = 50; 


let db;
try {
    db = new sqlite3.Database(DB_FILE, sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => { 
        if (err) {
            console.error('SQLite DB Bağlantı Hatası:', err.message);
            process.exit(1); 
        }
        console.log(`SQLite DB Bağlandı (${DB_FILE}).`);


        db.serialize(() => {
            db.run('PRAGMA foreign_keys = ON;', (err) => {
                 if (err) console.error("Foreign key pragma hatası:", err.message);
                 else console.log("Foreign key desteği etkinleştirildi.");
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
                    console.error("'users' tablosu oluşturma/kontrol hatası:", err.message);
                    process.exit(1);
                }
                console.log("'users' tablosu kontrol edildi/oluşturuldu.");
            });


            db.run(`CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id TEXT NOT NULL, -- 'general' veya 'private_userId1_userId2' (küçük id önce)
                sender_id INTEGER NOT NULL,
                recipient_id INTEGER, -- Özel mesajlarda alıcı ID, genel mesajlarda NULL
                text TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                -- is_read INTEGER DEFAULT 0, -- Okundu bilgisi (ileride eklenebilir)
                FOREIGN KEY (sender_id) REFERENCES users (id) ON DELETE CASCADE, -- Kullanıcı silinirse mesajları da sil (isteğe bağlı)
                FOREIGN KEY (recipient_id) REFERENCES users (id) ON DELETE SET NULL -- Alıcı silinirse ID'yi null yap (isteğe bağlı)
            )`, (err) => {
                 if (err) {
                    console.error("'messages' tablosu oluşturma/kontrol hatası:", err.message);
                    
                 }
                 else console.log("'messages' tablosu kontrol edildi/oluşturuldu.");
            });
        });
    });
} catch (error) {
    console.error("Veritabanı başlatma sırasında kritik hata:", error);
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
app.use(express.static(__dirname)); 


const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    console.log(`'${uploadsDir}' oluşturuluyor...`);
    fs.mkdirSync(uploadsDir, { recursive: true });
}
const publicSoundsDir = path.join(__dirname, 'public', 'sounds');
if (!fs.existsSync(publicSoundsDir)) {
     console.log(`'${publicSoundsDir}' oluşturuluyor...`);
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
        cb(new Error("Hata: Sadece resim dosyaları yüklenebilir (jpeg, jpg, png, gif)."));
    }
});

const getFullProfilePicUrl = (req, profilePicPath) => {
    if (!profilePicPath) return null; 
    const proto = req ? req.protocol : (process.env.NODE_ENV === 'production' ? 'https' : 'http');
    const host = req ? req.get('host') : (process.env.HOST || `https://metax.tr/api`); 

    const fullPath = profilePicPath.startsWith('/') ? profilePicPath : `/uploads/${profilePicPath}`;

    try {
        return new URL(fullPath, `${proto}://${host}`).toString();
    } catch (e) {
        console.error("Profil resmi URL oluşturma hatası:", e);
        return `${proto}://${host}${fullPath}`;
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
            if (profileFile) fs.unlinkSync(profileFile.path);
            return res.status(400).json({ message: 'Kullanıcı adı, e-posta ve şifre gereklidir.' });
        }


        const existingUser = await dbGet('SELECT id FROM users WHERE email = ? OR username = ?', [email.toLowerCase(), username]);
        if (existingUser) {
            if (profileFile) fs.unlinkSync(profileFile.path);
            return res.status(409).json({ message: 'Bu e-posta veya kullanıcı adı zaten kullanımda.' });
        }


        const hashedPassword = await bcrypt.hash(password, 10);

        const profilePicDbPath = profileFile ? profileFile.filename : null;


        const result = await dbRun(
            'INSERT INTO users (username, email, password_hash, profile_pic_path) VALUES (?, ?, ?, ?)',
            [username, email.toLowerCase(), hashedPassword, profilePicDbPath] 
        );
        const newUserId = result.lastID;
        console.log("Yeni Kullanıcı Kaydedildi (SQLite):", { id: newUserId, username });


        const token = jwt.sign({ userId: newUserId, email: email.toLowerCase() }, JWT_SECRET, { expiresIn: '24h' });


        res.status(201).json({
            message: 'Kayıt başarılı!',
            token,
            user: {
                id: newUserId,
                username,
                email: email.toLowerCase(),
                profilePic: getFullProfilePicUrl(req, profilePicDbPath ? `/uploads/${profilePicDbPath}` : null)
            }
        });

    } catch (error) {
        console.error("Kayıt Hatası:", error);

        if (profileFile && profileFile.path) {
            try { fs.unlinkSync(profileFile.path); } catch (e) { console.error("Resim silme hatası (kayıt sonrası):", e); }
        }

        if (error instanceof multer.MulterError || error.message?.includes('Hata: Sadece resim')) {
            return res.status(400).json({ message: error.message });
        }

        res.status(500).json({ message: 'Sunucu hatası oluştu. Lütfen tekrar deneyin.' });
    }
});


app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        if (!email || !password) {
            return res.status(400).json({ message: 'E-posta ve şifre gereklidir.' });
        }

        const user = await dbGet('SELECT id, username, email, password_hash, profile_pic_path FROM users WHERE email = ?', [email.toLowerCase()]);
        if (!user) {

            return res.status(401).json({ message: 'Geçersiz e-posta veya şifre.' });
        }


        const passwordMatch = await bcrypt.compare(password, user.password_hash);
        if (!passwordMatch) {

            return res.status(401).json({ message: 'Geçersiz e-posta veya şifre.' });
        }


        const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '24h' });
        console.log("Kullanıcı Giriş Yaptı (SQLite):", { id: user.id, username: user.username });


        res.status(200).json({
            message: 'Giriş başarılı!',
            token,
            user: {
                id: user.id,
                username: user.username,
                email: user.email, 
                profilePic: getFullProfilePicUrl(req, user.profile_pic_path ? `/uploads/${user.profile_pic_path}` : null)
            }
        });

    } catch (error) {
        console.error("Giriş Hatası:", error);
        res.status(500).json({ message: 'Sunucu hatası oluştu.' });
    }
});


const authenticateTokenHttp = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401); 

    jwt.verify(token, JWT_SECRET, (err, payload) => {
        if (err) {
            console.log("JWT Doğrulama Hatası (HTTP):", err.message);

            return res.status(403).json({ message: "Oturum geçersiz veya süresi dolmuş." });
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

            return res.status(404).json({ message: 'Kullanıcı bulunamadı.' });
        }
        console.log(`/api/me isteği başarılı (Kullanıcı: ${user.username}, ID: ${userId})`);

        res.status(200).json({
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                profilePic: getFullProfilePicUrl(req, user.profile_pic_path ? `/uploads/${user.profile_pic_path}` : null)
            }
        });
    } catch (error) {
        console.error("/api/me Hatası:", error);
        res.status(500).json({ message: 'Sunucu hatası.' });
    }
});




const broadcastOnlineUsers = () => {
    const usersArray = Array.from(onlineUsers.values()); 
    io.emit('updateUserList', usersArray);

};

io.on('connection', (socket) => {
    console.log(`Yeni Bağlantı: ${socket.id}`);



    socket.on('authenticate', async (token) => {
        try {
            if (!token) throw new Error('Token eksik');


            const decoded = jwt.verify(token, JWT_SECRET);

            const user = await dbGet('SELECT id, username, profile_pic_path FROM users WHERE id = ?', [decoded.userId]);
            if (!user) throw new Error('Kullanıcı veritabanında bulunamadı');


            const userData = {
                id: user.id,
                username: user.username,

                profilePic: getFullProfilePicUrl(null, user.profile_pic_path ? `/uploads/${user.profile_pic_path}` : null)
            };


            const existingSocketId = userIdToSocketIdMap.get(user.id);
            if (existingSocketId && existingSocketId !== socket.id) {
                const oldSocket = io.sockets.sockets.get(existingSocketId);
                if (oldSocket) {
                     console.log(`Kullanıcı ${user.username} için eski bağlantı (${existingSocketId}) kesiliyor.`);
                     oldSocket.disconnect(true);
                }
                onlineUsers.delete(existingSocketId); 
            }


            socket.user = userData;

            onlineUsers.set(socket.id, userData);

            userIdToSocketIdMap.set(user.id, socket.id);

            console.log(`Kullanıcı Doğrulandı: ${userData.username} (Socket ID: ${socket.id}, User ID: ${userData.id})`);



            socket.emit('auth_success', userData);

            io.emit('serverMessage', `${userData.username} sohbete katıldı.`); 

            broadcastOnlineUsers();

        } catch (error) {
            console.error(`Kimlik Doğrulama Hatası (${socket.id}):`, error.message);

            socket.emit('auth_failed');
            socket.disconnect(true);
        }
    });


    socket.on('chatMessage', async (msgText) => {

        if (!socket.user || typeof msgText !== 'string' || !msgText.trim()) return;

        const sanitizedMsg = msgText.trim(); 
        if (!sanitizedMsg) return; 

        const chatId = 'general';
        console.log(`[${chatId}] ${socket.user.username}: ${sanitizedMsg}`);

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
            console.error(`[${chatId}] Mesaj veritabanına kaydedilemedi:`, dbError);

            socket.emit('serverMessage', 'Mesajınız gönderilirken bir hata oluştu.');
        }
    });


    socket.on('privateMessage', async (data) => {

        if (!socket.user || !data || !data.recipientId || !data.text || typeof data.text !== 'string' || !data.text.trim()) {
            console.warn("Geçersiz özel mesaj verisi:", data, "- Gönderen:", socket.user?.username);
            return;
        }

        const recipientId = parseInt(data.recipientId);
        const senderId = socket.user.id;
        const sanitizedMsg = data.text.trim();
        if (!sanitizedMsg) return;

        if (isNaN(recipientId) || recipientId === senderId) {
            console.warn("Geçersiz alıcı ID veya kendine mesaj:", recipientId, "- Gönderen:", socket.user.username);
            socket.emit('serverMessage', 'Geçersiz alıcı veya kendinize mesaj gönderemezsiniz.');
            return;
        }


        const chatId = getPrivateChatIdServer(senderId, recipientId);
        if (!chatId) {
             console.error("Özel sohbet ID'si oluşturulamadı:", senderId, recipientId);
             socket.emit('serverMessage', 'Mesaj gönderilirken bir hata oluştu (chat ID).');
             return;
        }

        console.log(`[${chatId}] ${socket.user.username} -> Alıcı ID ${recipientId}: ${sanitizedMsg}`);

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
                console.log(` -> Mesaj ${recipientSocketId} ID'li alıcıya iletildi.`);
            } else {

                console.log(` -> Alıcı (ID: ${recipientId}) çevrimdışı.`);

            }


            socket.emit('newPrivateMessage', messageData);

        } catch (dbError) {
            console.error(`[${chatId}] Özel mesaj veritabanına kaydedilemedi:`, dbError);
            socket.emit('serverMessage', 'Mesajınız gönderilirken bir veritabanı hatası oluştu.');
        }
    });


    socket.on('requestHistory', async (data) => {
        if (!socket.user || !data || !data.chatId) {
            console.warn("Geçersiz geçmiş isteği:", data, "- Gönderen:", socket.user?.username);
            return;
        }
        const chatId = data.chatId;
        const userId = socket.user.id;

        console.log(`Kullanıcı ${userId} (${socket.user.username}), '${chatId}' sohbet geçmişini istedi.`);


        if (chatId.startsWith('private_')) {
            const ids = chatId.split('_');
            if (ids.length !== 3 || !ids.includes(String(userId))) {
                 console.warn(`Yetkisiz geçmiş isteği: Kullanıcı ${userId}, ${chatId} sohbetine ait değil.`);
                 socket.emit('chatHistory', { chatId, messages: [], error: "Bu sohbete erişim yetkiniz yok." });
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
                senderAvatar: getFullProfilePicUrl(null, row.senderAvatarPath ? `/uploads/${row.senderAvatarPath}` : null),
                isPrivate: chatId.startsWith('private_')
            }));

            console.log(`'${chatId}' için ${messages.length} adet geçmiş mesaj gönderiliyor.`);

            socket.emit('chatHistory', { chatId, messages });

        } catch (dbError) {
            console.error(`[${chatId}] Geçmiş yüklenirken veritabanı hatası:`, dbError);

            socket.emit('chatHistory', { chatId, messages: [], error: "Sohbet geçmişi yüklenirken bir hata oluştu." });
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
        console.log(`Bağlantı Kesildi: ${socket.id}, Sebep: ${reason}`);

        if (socket.user) {
            console.log(`${socket.user.username} (ID: ${socket.user.id}) ayrıldı.`);
            const userId = socket.user.id;

            onlineUsers.delete(socket.id);

            if (userIdToSocketIdMap.get(userId) === socket.id) {
                 userIdToSocketIdMap.delete(userId);
            }

            io.emit('serverMessage', `${socket.user.username} sohbetten ayrıldı.`);

            broadcastOnlineUsers();

             io.emit('userStoppedTyping', { userId: userId, chatId: 'general' }); 

        }
    });
});


server.listen(PORT, () => {
    console.log(`Sunucu http://localhost:${PORT} adresinde çalışıyor`);
    console.log(`Veritabanı dosyası: ${DB_FILE}`);
    console.log(`JWT Secret: ${JWT_SECRET.startsWith('cok-gizli') ? 'Varsayılan (Güvensiz!)' : 'Ayarlı'}`);
});

process.on('SIGINT', () => {
    console.log('\nKapatma sinyali alındı (SIGINT).');

    io.close(() => {
        console.log("Socket.IO sunucusu kapatıldı.");
    });

    db.close((err) => {
        if (err) {
            console.error("DB Kapatma Hatası:", err.message);
            process.exit(1);
        }
        console.log('SQLite veritabanı bağlantısı kapatıldı.');

        server.close(() => {
             console.log("HTTP sunucusu kapatıldı.");
             process.exit(0);
        });
        setTimeout(() => {
            console.error("Kapanma zaman aşımına uğradı, zorla çıkılıyor.");
            process.exit(1);
        }, 2000);
    });
});