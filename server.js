const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// In-memory storage (in production, use a database)
const users = new Map();
const channels = new Map();
const messages = new Map();
const userSockets = new Map();
const channelUsers = new Map();
const mutedUsers = new Map(); // channelId -> Set of muted aliases
const bannedUsers = new Map(); // channelId -> Set of banned aliases

// JWT secret (in production, use environment variable)
const JWT_SECRET = 'your-secret-key-here';

// Constants for alias locking
const TOKEN_EXPIRY_24H = '24h';
const TOKEN_EXPIRY_90D = '90d';
const ALIAS_LOCK_DURATION = 90 * 24 * 60 * 60 * 1000; // 90 days in milliseconds
const RENEWAL_WINDOW_DAYS = 14;
const RENEWAL_WINDOW_MS = RENEWAL_WINDOW_DAYS * 24 * 60 * 60 * 1000;

// Initialize channels and create owner account
const initializeApp = () => {
    // Create owner account
    const ownerAlias = 'uncleboof';
    const ownerPassword = bcrypt.hashSync('owner123', 10);
    
    users.set(ownerAlias, {
        alias: ownerAlias,
        password: ownerPassword,
        role: 'owner',
        expiresAt: null, // Never expires
        lockedUntil: null,
        createdAt: new Date().toISOString(),
        isPermanent: true
    });

    // Initialize channels
    const channelData = [
        { id: 1, name: 'General', password: null },
        { id: 2, name: 'Random', password: null },
        { id: 3, name: 'Private Group', password: 'secret123' },
        { id: 4, name: 'Tech Talk', password: null },
        { id: 5, name: 'Music Lovers', password: null },
        { id: 6, name: 'Book Club', password: null },
        { id: 7, name: 'Admin Only', password: 'admin123' },
        { id: 8, name: 'Sports', password: null },
        { id: 9, name: 'VIP Lounge', password: 'vip456' },
        { id: 10, name: 'Gaming', password: null },
        { id: 11, name: 'Movies', password: null },
        { id: 12, name: 'Foodies', password: null },
        { id: 13, name: 'Travel', password: null }
    ];

    channelData.forEach(channel => {
        channels.set(channel.id, channel);
        messages.set(channel.id, []);
        channelUsers.set(channel.id, new Set());
        mutedUsers.set(channel.id, new Set());
        bannedUsers.set(channel.id, new Set());
    });

    console.log('Owner account created: uncleboof');
    console.log('Default password: owner123');
};

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Authentication middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, error: 'Invalid token' });
        }

        // Check if user still exists and alias hasn't expired
        const userData = users.get(user.alias);
        if (!userData) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }

        // Skip expiry check for permanent users (owner)
        if (!userData.isPermanent) {
            const now = new Date();
            const expiresAt = new Date(userData.expiresAt);
            if (expiresAt < now) {
                return res.status(410).json({ success: false, error: 'Alias has expired' });
            }
        }

        req.user = user;
        next();
    });
}

// Helper function to check if user is admin or owner
function isAdmin(userAlias) {
    const user = users.get(userAlias);
    return user && (user.role === 'admin' || user.role === 'owner');
}

function isOwner(userAlias) {
    const user = users.get(userAlias);
    return user && user.role === 'owner';
}

// Routes
app.post('/api/register', async (req, res) => {
    const { alias, password } = req.body;

    if (!alias || !password) {
        return res.json({ success: false, error: 'Alias and password required' });
    }

    if (alias.length < 3 || alias.length > 16) {
        return res.json({ success: false, error: 'Alias must be 3-16 characters' });
    }

    if (password.length < 6) {
        return res.json({ success: false, error: 'Password must be at least 6 characters' });
    }

    if (users.has(alias)) {
        return res.json({ success: false, error: 'Alias already exists' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours from now
        
        const user = { 
            alias, 
            password: hashedPassword,
            expiresAt: expiresAt.toISOString(),
            lockedUntil: null,
            createdAt: new Date().toISOString(),
            role: 'user'
        };
        
        users.set(alias, user);

        const token = jwt.sign({ alias }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY_24H });
        
        res.json({ 
            success: true, 
            token,
            expiresAt: expiresAt.toISOString(),
            lockedUntil: null,
            role: 'user'
        });
    } catch (error) {
        res.json({ success: false, error: 'Registration failed' });
    }
});

app.post('/api/login', async (req, res) => {
    const { alias, password } = req.body;

    if (!alias || !password) {
        return res.json({ success: false, error: 'Alias and password required' });
    }

    const user = users.get(alias);
    if (!user) {
        return res.json({ success: false, error: 'User not found' });
    }

    // Check if alias is expired (skip for permanent users)
    if (!user.isPermanent) {
        const now = new Date();
        const expiresAt = new Date(user.expiresAt);
        if (expiresAt < now) {
            return res.json({ success: false, error: 'Alias has expired. Please register again.' });
        }
    }

    try {
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
            return res.json({ success: false, error: 'Invalid password' });
        }

        // Determine token expiry
        let tokenExpiry = user.isPermanent ? TOKEN_EXPIRY_90D : TOKEN_EXPIRY_24H;
        const lockedUntil = user.lockedUntil ? new Date(user.lockedUntil) : null;
        
        if (lockedUntil && lockedUntil > new Date() && !user.isPermanent) {
            tokenExpiry = TOKEN_EXPIRY_90D;
        }

        const token = jwt.sign({ alias }, JWT_SECRET, { expiresIn: tokenExpiry });
        
        res.json({ 
            success: true, 
            token,
            expiresAt: user.expiresAt,
            lockedUntil: user.lockedUntil,
            role: user.role
        });
    } catch (error) {
        res.json({ success: false, error: 'Login failed' });
    }
});

app.post('/api/lock-alias', authenticateToken, (req, res) => {
    const user = users.get(req.user.alias);
    
    if (!user) {
        return res.json({ success: false, error: 'User not found' });
    }

    // Permanent users don't need to lock their alias
    if (user.isPermanent) {
        return res.json({ success: false, error: 'Permanent aliases do not require locking' });
    }

    const now = new Date();
    const currentLockedUntil = user.lockedUntil ? new Date(user.lockedUntil) : null;
    
    // Check if user can renew (within last 14 days of lock period)
    const canRenew = currentLockedUntil && (currentLockedUntil.getTime() - now.getTime()) <= RENEWAL_WINDOW_MS;
    
    // Calculate new lockedUntil date
    let newLockedUntil;
    if (canRenew && currentLockedUntil) {
        // Renew: extend from current lockedUntil date
        newLockedUntil = new Date(currentLockedUntil.getTime() + ALIAS_LOCK_DURATION);
    } else {
        // New lock: start from now
        newLockedUntil = new Date(now.getTime() + ALIAS_LOCK_DURATION);
    }

    // Update user lock status and expiry
    user.lockedUntil = newLockedUntil.toISOString();
    user.expiresAt = newLockedUntil.toISOString();

    // Generate new token with 90-day expiry
    const token = jwt.sign({ alias: user.alias }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY_90D });

    res.json({
        success: true,
        token,
        expiresAt: user.expiresAt,
        lockedUntil: user.lockedUntil,
        action: canRenew ? 'renewed' : 'locked'
    });
});

// WebSocket connection handling
wss.on('connection', (ws) => {
    let currentUser = null;
    let currentChannel = null;

    ws.on('message', (data) => {
        try {
            const message = JSON.parse(data);
            handleWebSocketMessage(ws, message);
        } catch (error) {
            console.error('Error parsing message:', error);
        }
    });

    ws.on('close', () => {
        if (currentUser) {
            userSockets.delete(currentUser.alias);
            
            if (currentChannel) {
                leaveChannel(currentUser.alias, currentChannel.id);
            }
        }
    });

    const handleWebSocketMessage = (ws, message) => {
        switch (message.type) {
            case 'authenticate':
                handleAuthentication(ws, message);
                break;
            case 'get_channels':
                handleGetChannels(ws);
                break;
            case 'join_channel':
                handleJoinChannel(ws, message);
                break;
            case 'leave_channel':
                handleLeaveChannel(ws, message);
                break;
            case 'send_message':
                handleSendMessage(ws, message);
                break;
            case 'get_user_list':
                handleGetUserList(ws);
                break;
            case 'get_channel_users':
                handleGetChannelUsers(ws, message);
                break;
            case 'make_admin':
                handleMakeAdmin(ws, message);
                break;
            case 'remove_admin':
                handleRemoveAdmin(ws, message);
                break;
            case 'delete_user':
                handleDeleteUser(ws, message);
                break;
            case 'kick_user':
                handleKickUser(ws, message);
                break;
            case 'ban_user':
                handleBanUser(ws, message);
                break;
            case 'mute_user':
                handleMuteUser(ws, message);
                break;
            case 'delete_message':
                handleDeleteMessage(ws, message);
                break;
        }
    };

    const handleAuthentication = (ws, message) => {
        try {
            const decoded = jwt.verify(message.token, JWT_SECRET);
            const user = users.get(decoded.alias);
            
            if (user) {
                // Check if alias is expired (skip for permanent users)
                if (!user.isPermanent) {
                    const now = new Date();
                    const expiresAt = new Date(user.expiresAt);
                    if (expiresAt < now) {
                        ws.send(JSON.stringify({
                            type: 'auth_error',
                            error: 'Alias has expired'
                        }));
                        return;
                    }
                }

                currentUser = user;
                userSockets.set(user.alias, ws);
                
                ws.send(JSON.stringify({
                    type: 'auth_success',
                    alias: user.alias,
                    expiresAt: user.expiresAt,
                    lockedUntil: user.lockedUntil,
                    role: user.role
                }));
            } else {
                ws.send(JSON.stringify({
                    type: 'auth_error',
                    error: 'User not found'
                }));
            }
        } catch (error) {
            ws.send(JSON.stringify({
                type: 'auth_error',
                error: 'Invalid token'
            }));
        }
    };

    const handleGetChannels = (ws) => {
        const channelList = Array.from(channels.values()).map(channel => ({
            id: channel.id,
            name: channel.name,
            requiresPassword: channel.password !== null
        }));

        ws.send(JSON.stringify({
            type: 'channels_list',
            channels: channelList
        }));
    };

    const handleJoinChannel = (ws, message) => {
        if (!currentUser) {
            ws.send(JSON.stringify({
                type: 'channel_error',
                error: 'Not authenticated'
            }));
            return;
        }

        const channel = channels.get(message.channelId);
        if (!channel) {
            ws.send(JSON.stringify({
                type: 'channel_error',
                error: 'Channel not found'
            }));
            return;
        }

        // Check if user is banned from this channel
        const bannedInChannel = bannedUsers.get(channel.id);
        if (bannedInChannel && bannedInChannel.has(currentUser.alias)) {
            ws.send(JSON.stringify({
                type: 'channel_error',
                error: 'You are banned from this channel'
            }));
            return;
        }

        // Check password if required
        if (channel.password && channel.password !== message.password) {
            ws.send(JSON.stringify({
                type: 'channel_error',
                error: 'Invalid password'
            }));
            return;
        }

        // Leave previous channel if any
        if (currentChannel) {
            leaveChannel(currentUser.alias, currentChannel.id);
        }

        // Join new channel
        currentChannel = channel;
        channelUsers.get(channel.id).add(currentUser.alias);

        // Send channel history
        const channelHistory = messages.get(channel.id) || [];

        ws.send(JSON.stringify({
            type: 'channel_joined',
            channel: {
                id: channel.id,
                name: channel.name
            },
            history: channelHistory
        }));

        // Notify other users in the channel
        broadcastToChannel(channel.id, {
            type: 'users_in_channel',
            count: channelUsers.get(channel.id).size
        }, ws);
    };

    const handleLeaveChannel = (ws, message) => {
        if (currentUser && currentChannel) {
            leaveChannel(currentUser.alias, currentChannel.id);
            currentChannel = null;
        }
    };

    const handleSendMessage = (ws, message) => {
        if (!currentUser || !currentChannel) {
            return;
        }

        // Check if user is muted in this channel
        const mutedInChannel = mutedUsers.get(currentChannel.id);
        if (mutedInChannel && mutedInChannel.has(currentUser.alias)) {
            ws.send(JSON.stringify({
                type: 'error',
                error: 'You are muted in this channel'
            }));
            return;
        }

        const chatMessage = {
            id: Date.now(),
            text: message.text,
            sender: currentUser.alias,
            timestamp: new Date().toISOString(),
            channelId: currentChannel.id
        };

        // Store message
        const channelMessages = messages.get(currentChannel.id) || [];
        channelMessages.push(chatMessage);
        messages.set(currentChannel.id, channelMessages);

        // Broadcast to all users in the channel
        broadcastToChannel(currentChannel.id, {
            type: 'message',
            message: chatMessage
        });
    };

    // Admin functions
    const handleGetUserList = (ws) => {
        if (!currentUser || !isAdmin(currentUser.alias)) {
            return;
        }

        const userList = Array.from(users.values()).map(user => ({
            alias: user.alias,
            role: user.role,
            expiresAt: user.expiresAt,
            isMuted: Array.from(mutedUsers.values()).some(mutedSet => mutedSet.has(user.alias))
        }));

        ws.send(JSON.stringify({
            type: 'user_list',
            users: userList
        }));
    };

    const handleGetChannelUsers = (ws, message) => {
        if (!currentUser || !isAdmin(currentUser.alias)) {
            return;
        }

        const channelId = message.channelId;
        const usersInChannel = channelUsers.get(channelId);
        
        if (!usersInChannel) {
            return;
        }

        const userList = Array.from(usersInChannel).map(alias => {
            const user = users.get(alias);
            const isMuted = mutedUsers.get(channelId)?.has(alias) || false;
            
            return {
                alias: alias,
                role: user ? user.role : 'user',
                isMuted: isMuted
            };
        });

        ws.send(JSON.stringify({
            type: 'channel_users',
            users: userList
        }));
    };

    const handleMakeAdmin = (ws, message) => {
        if (!currentUser || !isOwner(currentUser.alias)) {
            return;
        }

        const targetUser = users.get(message.alias);
        if (targetUser && targetUser.role !== 'owner') {
            targetUser.role = 'admin';
            
            // Notify the user
            const targetWs = userSockets.get(message.alias);
            if (targetWs) {
                targetWs.send(JSON.stringify({
                    type: 'admin_status',
                    alias: message.alias,
                    isAdmin: true,
                    isOwner: false,
                    action: 'added'
                }));
            }

            // Notify all admins
            broadcastToAdmins({
                type: 'user_list_updated'
            });
        }
    };

    const handleRemoveAdmin = (ws, message) => {
        if (!currentUser || !isOwner(currentUser.alias)) {
            return;
        }

        const targetUser = users.get(message.alias);
        if (targetUser && targetUser.role === 'admin') {
            targetUser.role = 'user';
            
            // Notify the user
            const targetWs = userSockets.get(message.alias);
            if (targetWs) {
                targetWs.send(JSON.stringify({
                    type: 'admin_status',
                    alias: message.alias,
                    isAdmin: false,
                    isOwner: false,
                    action: 'removed'
                }));
            }

            // Notify all admins
            broadcastToAdmins({
                type: 'user_list_updated'
            });
        }
    };

    const handleDeleteUser = (ws, message) => {
        if (!currentUser || !isOwner(currentUser.alias)) {
            return;
        }

        const targetAlias = message.alias;
        if (targetAlias === currentUser.alias) {
            ws.send(JSON.stringify({
                type: 'error',
                error: 'Cannot delete your own account'
            }));
            return;
        }

        const targetUser = users.get(targetAlias);
        if (targetUser && targetUser.role !== 'owner') {
            // Remove user from all channels
            for (const [channelId, usersInChannel] of channelUsers) {
                usersInChannel.delete(targetAlias);
                broadcastToChannel(channelId, {
                    type: 'users_in_channel',
                    count: usersInChannel.size
                });
            }

            // Remove user data
            users.delete(targetAlias);
            userSockets.delete(targetAlias);

            // Notify all admins
            broadcastToAdmins({
                type: 'user_list_updated'
            });
        }
    };

    const handleKickUser = (ws, message) => {
        if (!currentUser || !isAdmin(currentUser.alias)) {
            return;
        }

        const targetAlias = message.alias;
        const channelId = message.channelId;
        
        if (targetAlias === currentUser.alias) {
            return; // Can't kick yourself
        }

        const targetUser = users.get(targetAlias);
        if (targetUser && targetUser.role !== 'owner') {
            // Remove user from channel
            const usersInChannel = channelUsers.get(channelId);
            if (usersInChannel) {
                usersInChannel.delete(targetAlias);
                
                // Notify the kicked user
                const targetWs = userSockets.get(targetAlias);
                if (targetWs) {
                    targetWs.send(JSON.stringify({
                        type: 'user_kicked',
                        alias: targetAlias,
                        channelName: channels.get(channelId).name
                    }));
                }

                // Update user count for remaining users
                broadcastToChannel(channelId, {
                    type: 'users_in_channel',
                    count: usersInChannel.size
                });

                // Notify admins
                broadcastToAdmins({
                    type: 'user_list_updated'
                });
            }
        }
    };

    const handleBanUser = (ws, message) => {
        if (!currentUser || !isAdmin(currentUser.alias)) {
            return;
        }

        const targetAlias = message.alias;
        const channelId = message.channelId;
        
        if (targetAlias === currentUser.alias) {
            return; // Can't ban yourself
        }

        const targetUser = users.get(targetAlias);
        if (targetUser && targetUser.role !== 'owner') {
            // Add to banned list
            const bannedInChannel = bannedUsers.get(channelId);
            if (bannedInChannel) {
                bannedInChannel.add(targetAlias);
            }

            // Remove user from channel
            const usersInChannel = channelUsers.get(channelId);
            if (usersInChannel) {
                usersInChannel.delete(targetAlias);
                
                // Notify the banned user
                const targetWs = userSockets.get(targetAlias);
                if (targetWs) {
                    targetWs.send(JSON.stringify({
                        type: 'user_banned',
                        alias: targetAlias,
                        channelName: channels.get(channelId).name
                    }));
                }

                // Update user count for remaining users
                broadcastToChannel(channelId, {
                    type: 'users_in_channel',
                    count: usersInChannel.size
                });

                // Notify admins
                broadcastToAdmins({
                    type: 'user_list_updated'
                });
            }
        }
    };

    const handleMuteUser = (ws, message) => {
        if (!currentUser || !isAdmin(currentUser.alias)) {
            return;
        }

        const targetAlias = message.alias;
        const channelId = message.channelId;
        const mute = message.mute;
        
        if (targetAlias === currentUser.alias) {
            return; // Can't mute yourself
        }

        const targetUser = users.get(targetAlias);
        if (targetUser && targetUser.role !== 'owner') {
            const mutedInChannel = mutedUsers.get(channelId);
            if (mutedInChannel) {
                if (mute) {
                    mutedInChannel.add(targetAlias);
                } else {
                    mutedInChannel.delete(targetAlias);
                }

                // Notify the user
                const targetWs = userSockets.get(targetAlias);
                if (targetWs) {
                    targetWs.send(JSON.stringify({
                        type: 'user_muted',
                        alias: targetAlias,
                        channelName: channels.get(channelId).name,
                        mute: mute
                    }));
                }

                // Notify admins
                broadcastToAdmins({
                    type: 'user_list_updated'
                });
            }
        }
    };

    const handleDeleteMessage = (ws, message) => {
        if (!currentUser || !isAdmin(currentUser.alias)) {
            return;
        }

        const messageId = message.messageId;
        
        // Find and remove the message from all channels
        for (const [channelId, channelMessages] of messages) {
            const messageIndex = channelMessages.findIndex(msg => msg.id == messageId);
            if (messageIndex !== -1) {
                channelMessages.splice(messageIndex, 1);
                
                // Notify all users in the channel
                broadcastToChannel(channelId, {
                    type: 'message_deleted',
                    messageId: messageId
                });
                break;
            }
        }
    };

    const leaveChannel = (userAlias, channelId) => {
        const usersInChannel = channelUsers.get(channelId);
        if (usersInChannel) {
            usersInChannel.delete(userAlias);
            
            broadcastToChannel(channelId, {
                type: 'users_in_channel',
                count: usersInChannel.size
            });
        }
    };

    const broadcastToChannel = (channelId, data, excludeWs = null) => {
        const usersInChannel = channelUsers.get(channelId);
        if (usersInChannel) {
            usersInChannel.forEach(userAlias => {
                const userWs = userSockets.get(userAlias);
                if (userWs && userWs !== excludeWs && userWs.readyState === WebSocket.OPEN) {
                    userWs.send(JSON.stringify(data));
                }
            });
        }
    };

    const broadcastToAdmins = (data) => {
        userSockets.forEach((ws, alias) => {
            if (isAdmin(alias) && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify(data));
            }
        });
    };
});

// Serve the frontend
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Initialize and start server
initializeApp();

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log('Access the chat app at: http://localhost:' + PORT);
    console.log('Owner account: uncleboof / owner123');
});