iMessage-Style Chat Application
===============================

A real-time chat application with iMessage styling, user accounts, alias locking, and admin moderation features.

Features:
- iMessage-style user interface
- User accounts with alias locking system
- Real-time messaging via WebSockets
- 13 channels (3 password-protected)
- Owner account (uncleboof) with full moderation
- Admin system with user management
- Message deletion, user muting/kicking/banning
- Alias renewal system (90-day locks with 14-day renewal window)

Quick Local Setup
=================

1. INSTALL NODE.JS
   ---------------
   Download and install Node.js from: https://nodejs.org
   (Choose the LTS version)

2. CREATE PROJECT FOLDER
   ---------------------
   Create a folder for your chat app:

   Windows:
     mkdir chat-app
     cd chat-app
     mkdir public

   Mac/Linux:
     mkdir chat-app
     cd chat-app
     mkdir public

3. ADD THE FILES
   -------------
   Place these 3 files in the correct locations:

   chat-app/
   ├── server.js          (place this in chat-app folder)
   ├── package.json       (place this in chat-app folder)
   └── public/
       └── index.html     (place this in public folder)

4. INSTALL DEPENDENCIES
   --------------------
   In the chat-app folder, run:

   npm install

   This will install:
   - express (web server)
   - ws (WebSocket support)
   - bcryptjs (password encryption)
   - jsonwebtoken (authentication)

5. START THE SERVER
   ----------------
   In the chat-app folder, run:

   npm start

   You should see:
   "Server running on port 3000"
   "Access the chat app at: http://localhost:3000"
   "Owner account: uncleboof / owner123"

6. ACCESS THE APP
   --------------
   Open a web browser and go to:
   http://localhost:3000

   For other devices on the same network:
   http://[YOUR-IP-ADDRESS]:3000

   To find your IP address:
   - Windows: Run "ipconfig" in Command Prompt
   - Mac: Run "ifconfig" in Terminal
   - Linux: Run "ip addr show" in Terminal

Default Accounts & Channels
===========================

Owner Account:
- Username: uncleboof
- Password: owner123
- Permanent alias (never expires)
- Full admin privileges

Password-Protected Channels:
- Channel 3: "Private Group" - Password: secret123
- Channel 7: "Admin Only" - Password: admin123
- Channel 9: "VIP Lounge" - Password: vip456

Regular Channels (no password):
- Channel 1: General
- Channel 2: Random
- Channel 4: Tech Talk
- Channel 5: Music Lovers
- Channel 6: Book Club
- Channel 8: Sports
- Channel 10: Gaming
- Channel 11: Movies
- Channel 12: Foodies
- Channel 13: Travel

Alias Locking System
====================

- New aliases expire after 24 hours
- Users can "Lock Alias" to extend for 90 days
- During the last 14 days of a lock period, users can "Renew Alias"
- Active users can maintain their alias indefinitely by renewing
- Owner account (uncleboof) has permanent alias

Admin Features
==============

Owner (uncleboof) can:
- Make other users admins
- Remove admin privileges
- Delete any user account
- All regular admin features

Admins can:
- Delete messages in any channel
- Mute users in channels
- Kick users from channels
- Ban users from channels
- View all users in admin panel

Development
===========

For development with auto-restart:
npm run dev

(Requires nodemon: npm install -g nodemon)

File Structure
==============

chat-app/
├── server.js          # Backend server (Node.js/Express/WebSocket)
├── package.json       # Dependencies and scripts
└── public/
    └── index.html     # Frontend (HTML/CSS/JavaScript)

Troubleshooting
===============

Port already in use:
- Change PORT in server.js (line near bottom)
- Or kill process using port 3000

Cannot connect from other devices:
- Check firewall settings
- Ensure devices are on same network
- Verify IP address is correct

Dependencies won't install:
- Ensure Node.js is properly installed
- Try: npm cache clean --force
- Then: npm install

Security Notes
==============

- This is designed for LOCAL NETWORK use only
- For internet access, additional security needed
- Change default passwords in production
- Use environment variables for JWT secret in production