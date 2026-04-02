const express   = require('express');
const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcode    = require('qrcode-terminal');
const QRCode    = require('qrcode');
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
// Full message store: array of { id, body, ts }
// Lets us search by name, phone, item — not just order ID
let messageStore = [];   // all cached group messages (capped at MAX_CACHE_SIZE)
let orderIdIndex = new Map(); // orderId → serialized message id (fast lookup)

function loadCache() {
    try {
        if (fs.existsSync(CACHE_FILE)) {
            const raw  = fs.readFileSync(CACHE_FILE, 'utf8');
            const data = JSON.parse(raw);
            messageStore = data.store || [];
            const idx    = data.index || {};
            orderIdIndex = new Map(Object.entries(idx));
            console.log(`📦 Loaded ${messageStore.length} messages + ${orderIdIndex.size} order IDs from disk.`);
        }
    } catch (e) {
        console.log('⚠️  Could not load message cache:', e.message);
        messageStore = []; orderIdIndex = new Map();
    }
}

function saveCache() {
    try {
        if (messageStore.length > MAX_CACHE_SIZE) {
            messageStore = messageStore.slice(-MAX_CACHE_SIZE);
        }
        fs.writeFileSync(CACHE_FILE, JSON.stringify({
            store: messageStore,
            index: Object.fromEntries(orderIdIndex),
        }), 'utf8');
    } catch (e) {
        console.log('⚠️  Could not save message cache:', e.message);
    }
}

function extractOrderIds(text) {
    if (!text) return [];
    return [...text.matchAll(/Order\s?#?(\d+)/gi)].map(m => m[1]);
}

/** Store an incoming message body + ID so we can search it later */
function cacheMessage(serializedId, body) {
    if (!body || !serializedId) return;

    // Add to full store
    messageStore.push({ id: serializedId, body, ts: Date.now() });

    // Index any order IDs mentioned
    const ids = extractOrderIds(body);
    ids.forEach(oid => {
        orderIdIndex.set(oid, serializedId);
        console.log(`📌 Indexed Order #${oid} → message`);
    });

    saveCache();
}

/**
 * Smart search: finds the best matching cached message for an order.
 * Priority: 1) exact order ID  2) phone number  3) customer name  4) item name
 */
function findBestMatch(orderId, customerName, customerPhone, items) {
    // 1. Exact order ID index
    if (orderId && orderIdIndex.has(String(orderId))) {
        console.log(`🎯 Matched by Order ID`);
        return orderIdIndex.get(String(orderId));
    }

    // Normalise search terms
    const phoneClean  = (customerPhone || '').replace(/\D/g, '').slice(-10); // last 10 digits
    const nameLower   = (customerName  || '').toLowerCase().trim();
    const itemsLower  = (items         || '').toLowerCase();

    // Build name tokens (each word separately, skip short ones)
    const nameTokens  = nameLower.split(/\s+/).filter(t => t.length > 2);

    // Search newest-first so we find the most recent relevant message
    for (let i = messageStore.length - 1; i >= 0; i--) {
        const { id, body } = messageStore[i];
        const bodyLower = body.toLowerCase();
        const bodyDigits = body.replace(/\D/g, '');

        // 2. Phone number match (last 10 digits anywhere in body)
        if (phoneClean && bodyDigits.includes(phoneClean)) {
            console.log(`🎯 Matched by phone number`);
            return id;
        }

        // 3. Customer name match (all name tokens found in body)
        if (nameTokens.length > 0 && nameTokens.every(t => bodyLower.includes(t))) {
            console.log(`🎯 Matched by customer name: ${customerName}`);
            return id;
        }

        // 4. Item name match (any item keyword found in body)
        if (itemsLower) {
            const itemTokens = itemsLower.split(/[,\s]+/).filter(t => t.length > 3);
            const matchedItem = itemTokens.find(t => bodyLower.includes(t));
            if (matchedItem) {
                console.log(`🎯 Matched by item: ${matchedItem}`);
                return id;
            }
        }
    }

    return null;
}

loadCache();

// ─────────────────────────────────────────────
// WHATSAPP CLIENT
// ─────────────────────────────────────────────
const client = new Client({
    authStrategy: new LocalAuth(),
    // Pin a stable WhatsApp Web version — prevents mid-session navigation
    // that destroys the Puppeteer execution context
    webVersionCache: {
        type: 'local',
        strict: false,
    },
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
            '--single-process',
            '--disable-extensions',
            '--disable-background-networking',
            '--disable-default-apps',
            '--disable-sync',
            '--no-default-browser-check',
            '--window-size=1280,720',
        ],
        handleSIGINT: false,
        protocolTimeout: 60000,   // 60s — not infinite (0 was causing hangs)
        defaultViewport: null,
    }
});

let clientReady = false;
let latestQr    = null;   // raw QR string — served at /qr

client.on('qr', (qr) => {
    latestQr = qr;
    const host = process.env.RAILWAY_PUBLIC_DOMAIN
        ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`
        : `http://localhost:${process.env.PORT || 3000}`;
    console.log(`🤖 SCAN QR CODE → ${host}/qr`);
    qrcode.generate(qr, { small: true });
});

client.on('ready', () => {
    clientReady = true;
    console.log('✅ CLAWBOT IS ONLINE AND LOCKED ONTO YOUR GROUP!');
});

client.on('disconnected', (reason) => {
    clientReady = false;
    console.log('❌ WhatsApp Disconnected:', reason);
    setTimeout(() => {
        console.log('🔄 Attempting to reinitialize WhatsApp client...');
        startClient();
    }, 5000);
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

app.get('/qr', async (_req, res) => {
    if (clientReady) {
        return res.send('<h2 style="font-family:sans-serif;color:green">✅ Already authenticated — no QR needed.</h2>');
    }
    if (!latestQr) {
        return res.send('<h2 style="font-family:sans-serif;color:orange">⏳ QR not ready yet — refresh in a few seconds.</h2>');
    }
    try {
        const dataUrl = await QRCode.toDataURL(latestQr, { scale: 8 });
        res.send(`<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Clawbot QR</title>
<meta http-equiv="refresh" content="30">
<style>body{font-family:sans-serif;text-align:center;padding:40px;background:#111;color:#eee;}
img{border:12px solid #fff;border-radius:12px;}</style></head>
<body><h2>📱 Scan with WhatsApp</h2>
<p style="color:#aaa;font-size:13px;">Page auto-refreshes every 30s</p>
<img src="${dataUrl}" alt="QR Code"/></body></html>`);
    } catch (e) {
        res.status(500).send('QR generation error: ' + e.message);
    }
});

app.get('/health', (_req, res) => {
    res.json({
        status: 'ok',
        cachedOrders: orderIdIndex.size,
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
    const { orderId, message, customerName, customerPhone, items } = req.body;
    if (!orderId || !message) {
        return res.status(400).json({ success: false, error: 'orderId and message are required' });
    }

    // Strip any "Order #" prefix Python may have already included
    const cleanId = String(orderId).replace(/^Order\s*#?\s*/i, '').trim();
    console.log(`\n📥 Outbound update for Order #${cleanId} (${customerName || 'unknown'})...`);

    if (!clientReady) {
        console.log('⚠️  Client not ready yet — rejecting request.');
        return res.status(503).json({ success: false, error: 'WhatsApp client not ready. Try again in a moment.' });
    }

    try {
        const cachedId = findBestMatch(cleanId, customerName, customerPhone, items);
        let sentMsg;

        if (cachedId) {
            console.log(`🔍 Cache hit — fetching single message ${cachedId.substring(0, 30)}...`);
            try {
                const originalMsg = await Promise.race([
                    client.getMessageById(cachedId),
                    new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 8000))
                ]);
                sentMsg = await originalMsg.reply(message);
                console.log(`✅ Replied/quoted original Order #${cleanId} message.`);
            } catch (lookupErr) {
                console.log(`⚠️  Cache lookup failed (${lookupErr.message}) — sending as new message.`);
                sentMsg = await client.sendMessage(SAVED_GROUP_ID, message);
            }
        } else {
            console.log(`📭 No cache for Order #${cleanId} — sending as new message.`);
            sentMsg = await client.sendMessage(SAVED_GROUP_ID, message);
        }

        // Cache sent message so future calls can reply to it
        if (sentMsg && sentMsg.id) {
            cacheMessage(sentMsg.id._serialized, message);
        }

        res.status(200).json({ success: true, quoted: !!cachedId });

    } catch (error) {
        console.error('❌ Send Error:', error.message);

        // Detached frame = Puppeteer page died mid-send. The 'disconnected'
        // event won't fire, so we must force a full reconnect ourselves.
        if (error.message && (error.message.includes('detached Frame') || error.message.includes('Execution context'))) {
            console.log('🔄 Detached frame — forcing reconnect...');
            clientReady = false;
            try { await client.destroy(); } catch (_) {}
            startClient();
        }

        res.status(500).json({ success: false, error: error.message });
    }
});

// ─────────────────────────────────────────────
// BOOT
// ─────────────────────────────────────────────
async function startClient(attempt = 1) {
    try {
        await client.initialize();
    } catch (e) {
        const wait = Math.min(attempt * 5000, 30000); // 5s → 10s → 15s … max 30s
        console.log(`⚠️  Initialize failed (attempt ${attempt}): ${e.message}. Retrying in ${wait / 1000}s...`);
        // Kill the orphaned Chromium process so the next attempt can acquire the lock
        try { await client.destroy(); } catch (_) {}
        setTimeout(() => startClient(attempt + 1), wait);
    }
}
startClient();

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🤖 API listening on port ${PORT}`);
});
