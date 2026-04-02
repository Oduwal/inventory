const express = require('express');
const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcode    = require('qrcode-terminal');
const axios     = require('axios');
const fs        = require('fs');
const path      = require('path');

console.log('🚀 Booting up Clawbot (Production Mode)...');

// ─────────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────────
const SAVED_GROUP_ID = process.env.WA_GROUP_ID   || "120363239510350827@g.us";
const PYTHON_APP_URL = process.env.PYTHON_APP_URL || "https://inventory-production-d41e.up.railway.app";
const CACHE_FILE     = path.join(__dirname, 'message_cache.json');
const MAX_CACHE_SIZE = 2000; // rolling cap — oldest dropped first

// ─────────────────────────────────────────────
// MESSAGE ID CACHE  (orderId → serialized msg id)
// This is the core fix: we NEVER call fetchMessages().
// Instead we passively intercept every message and store its ID.
// ─────────────────────────────────────────────
let messageCache = new Map(); // orderId (string) → serialized id (string)

function loadCache() {
    try {
        if (fs.existsSync(CACHE_FILE)) {
            const raw  = fs.readFileSync(CACHE_FILE, 'utf8');
            const data = JSON.parse(raw);
            messageCache = new Map(Object.entries(data));
            console.log(`📦 Loaded ${messageCache.size} cached message IDs from disk.`);
        }
    } catch (e) {
        console.log('⚠️  Could not load message cache:', e.message);
    }
}

function saveCache() {
    try {
        // Trim to MAX_CACHE_SIZE — drop oldest entries (Map preserves insertion order)
        if (messageCache.size > MAX_CACHE_SIZE) {
            const keys = [...messageCache.keys()];
            keys.slice(0, messageCache.size - MAX_CACHE_SIZE).forEach(k => messageCache.delete(k));
        }
        const obj = Object.fromEntries(messageCache);
        fs.writeFileSync(CACHE_FILE, JSON.stringify(obj), 'utf8');
    } catch (e) {
        console.log('⚠️  Could not save message cache:', e.message);
    }
}

/** Extract all order IDs mentioned in a message body */
function extractOrderIds(text) {
    if (!text) return [];
    const matches = [...text.matchAll(/Order\s?#?(\d+)/gi)];
    return matches.map(m => m[1]);
}

/** Store message ID in cache for every order ID found in the text */
function cacheMessage(msgId, text) {
    const ids = extractOrderIds(text);
    if (ids.length === 0) return;
    ids.forEach(orderId => {
        messageCache.set(orderId, msgId);
        console.log(`📌 Cached message id for Order #${orderId}`);
    });
    saveCache();
}

loadCache();

// ─────────────────────────────────────────────
// WHATSAPP CLIENT
// ─────────────────────────────────────────────
const client = new Client({
    authStrategy: new LocalAuth(),
    puppeteer: {
        headless: true,
        args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
            '--disable-accelerated-2d-canvas',
            '--no-first-run',
            '--no-zygote',
            '--disable-gpu',
            '--single-process',          // critical for low-RAM containers
            '--disable-extensions',
        ],
        handleSIGINT: false,
        protocolTimeout: 0,
    }
});

client.on('qr', (qr) => {
    console.log('🤖 SCAN QR CODE:');
    qrcode.generate(qr, { small: true });
});

client.on('ready', () => {
    console.log('✅ CLAWBOT IS ONLINE AND LOCKED ONTO YOUR GROUP!');
});

client.on('disconnected', (reason) => {
    console.log('❌ WhatsApp Disconnected:', reason);
});

// ─────────────────────────────────────────────
// INBOUND LISTENER
// Passively caches every group message that mentions an order.
// Also forwards replies-to-order-messages back to Python.
// ─────────────────────────────────────────────
client.on('message', async (msg) => {
    // Only care about our target group
    const chatId = msg.from || '';
    if (chatId !== SAVED_GROUP_ID) return;

    // Cache any order IDs mentioned in this message body
    if (msg.body) {
        cacheMessage(msg.id._serialized, msg.body);
    }

    // If this is a reply to another message, check if that original message
    // had an order ID → notify Python dashboard
    if (msg.hasQuotedMsg) {
        try {
            const quoted = await msg.getQuotedMessage();
            const ids    = extractOrderIds(quoted.body || '');

            // Also cache the quoted message itself while we have it
            if (quoted.body) cacheMessage(quoted.id._serialized, quoted.body);

            if (ids.length > 0) {
                const orderId = ids[0];
                console.log(`🔔 Reply to Order #${orderId} detected — notifying dashboard...`);
                await axios.post(`${PYTHON_APP_URL}/api/whatsapp-webhook`, {
                    order_id:     orderId,
                    comment:      msg.body,
                    sender_phone: msg.author || msg.from,
                }).catch(e => console.log('⚠️  Could not reach Python app:', e.message));
            }
        } catch (e) {
            console.log('Error processing quoted message:', e.message);
        }
    }
});

// ─────────────────────────────────────────────
// EXPRESS API
// ─────────────────────────────────────────────
const app = express();
app.use(express.json());

app.get('/health', (_req, res) => {
    res.json({
        status: 'ok',
        cachedOrders: messageCache.size,
        waConnected: client.info ? true : false,
    });
});

/**
 * POST /send-group-feedback
 * Body: { orderId, message, groupName? }
 *
 * Strategy:
 *  1. Look up orderId in the cache → get the original message's serialized ID
 *  2. Fetch ONLY that one message via client.getMessageById()  ← no fetchMessages() ever
 *  3. Reply/quote it
 *  4. If not cached → send as a new message (fallback)
 *  5. Cache the sent/replied message ID so future calls can reply to it
 */
app.post('/send-group-feedback', async (req, res) => {
    const { orderId, message } = req.body;
    if (!orderId || !message) {
        return res.status(400).json({ success: false, error: 'orderId and message are required' });
    }

    console.log(`\n📥 Outbound update for Order #${orderId}...`);

    try {
        const cachedId = messageCache.get(String(orderId));
        let sentMsg;

        if (cachedId) {
            console.log(`🔍 Cache hit — fetching single message ${cachedId.substring(0, 30)}...`);
            try {
                // Lightweight: fetches ONE message by ID — never the full history
                const originalMsg = await Promise.race([
                    client.getMessageById(cachedId),
                    new Promise((_, rej) => setTimeout(() => rej(new Error('getMessageById timeout')), 8000))
                ]);
                sentMsg = await originalMsg.reply(message);
                console.log(`✅ Replied to original Order #${orderId} message.`);
            } catch (lookupErr) {
                console.log(`⚠️  Could not fetch cached message (${lookupErr.message}) — falling back to new message.`);
                sentMsg = await client.sendMessage(SAVED_GROUP_ID, message);
            }
        } else {
            console.log(`📭 No cache for Order #${orderId} — sending as new message.`);
            sentMsg = await client.sendMessage(SAVED_GROUP_ID, message);
        }

        // Cache the sent/replied message so future calls can reply to it
        if (sentMsg && sentMsg.id) {
            cacheMessage(sentMsg.id._serialized, message);
        }

        res.status(200).json({ success: true, quoted: !!cachedId });

    } catch (error) {
        console.error('❌ Send Error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ─────────────────────────────────────────────
// BOOT
// ─────────────────────────────────────────────
client.initialize();

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🤖 API listening on port ${PORT}`);
});
