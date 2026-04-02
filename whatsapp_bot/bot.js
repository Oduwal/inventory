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
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || "";
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
let msgToOrderId = new Map(); // reverse: serialized message id → orderId
let orderDetails = new Map(); // orderId → { customerName, customerPhone, items }
                               // populated every time Python sends an update so we
                               // can match replies even if the original msg was never cached

function loadCache() {
    try {
        if (fs.existsSync(CACHE_FILE)) {
            const raw  = fs.readFileSync(CACHE_FILE, 'utf8');
            const data = JSON.parse(raw);
            messageStore = data.store || [];
            const idx    = data.index || {};
            orderIdIndex = new Map(Object.entries(idx));
            const rev    = data.reverse || {};
            msgToOrderId = new Map(Object.entries(rev));
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
            store:   messageStore,
            index:   Object.fromEntries(orderIdIndex),
            reverse: Object.fromEntries(msgToOrderId),
        }), 'utf8');
    } catch (e) {
        console.log('⚠️  Could not save message cache:', e.message);
    }
}

function extractOrderIds(text) {
    if (!text) return [];
    return [...text.matchAll(/Order\s?#?(\d+)/gi)].map(m => m[1]);
}

/**
 * Store a message body + ID so we can search it later.
 * @param {boolean} indexOrders - false for bot-sent messages so we never
 *   overwrite the original group message in orderIdIndex.
 */
function cacheMessage(serializedId, body, indexOrders = true, isSent = false) {
    if (!body || !serializedId) return;

    messageStore.push({ id: serializedId, body, ts: Date.now(), sent: isSent });

    if (indexOrders) {
        const ids = extractOrderIds(body);
        ids.forEach(oid => {
            // First seen wins — never overwrite an existing mapping with a
            // later message (which could be the bot's own reply).
            if (!orderIdIndex.has(oid)) {
                orderIdIndex.set(oid, serializedId);
                console.log(`📌 Indexed Order #${oid} → message`);
            }
        });
    }

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

    // Search newest-first, skipping bot-sent messages (they contain customer
    // name/phone in their body but are not the original group order message)
    for (let i = messageStore.length - 1; i >= 0; i--) {
        const { id, body, sent } = messageStore[i];
        if (sent) continue; // never match our own outbound messages
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

// Chromium leaves singleton lock files when it crashes / container is killed.
// On next boot the new process sees them and refuses to start.
// Always wipe them before initialising.
const CHROME_LOCK_FILES = [
    path.join(__dirname, '.wwebjs_auth', 'session', 'SingletonLock'),
    path.join(__dirname, '.wwebjs_auth', 'session', 'SingletonCookie'),
    path.join(__dirname, '.wwebjs_auth', 'session', 'SingletonSocket'),
];
function clearChromeLocks() {
    CHROME_LOCK_FILES.forEach(f => {
        try { fs.unlinkSync(f); console.log(`🗑️  Removed stale lock: ${path.basename(f)}`); } catch (_) {}
    });
}

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
let latestQr    = null;
const sendQueue = new Map();

/** Quick Puppeteer ping — returns false if the page/frame is in a bad state */
async function isPageAlive() {
    try {
        if (!client.pupPage) return false;
        await client.pupPage.evaluate(() => true);
        return true;
    } catch (_) {
        return false;
    }
}

client.on('qr', (qr) => {
    latestQr = qr;
    const host = process.env.RAILWAY_PUBLIC_DOMAIN
        ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`
        : `http://localhost:${process.env.PORT || 3000}`;
    console.log(`🤖 SCAN QR CODE → ${host}/qr`);
    qrcode.generate(qr, { small: true });
});

client.on('ready', () => {
    console.log('🔗 WA connected — warming up for 10s...');
    setTimeout(() => {
        clientReady = true;
        console.log('✅ CLAWBOT IS ONLINE AND LOCKED ONTO YOUR GROUP!');

        // Proactively detect frame detachment so we pause sends BEFORE
        // they fail, rather than reacting after the error.
        if (client.pupPage) {
            client.pupPage.on('framedetached', () => {
                if (!clientReady) return; // already handling it
                console.log('⚠️  Puppeteer frame detached — pausing sends...');
                clientReady = false;
                // Give WA Web 8s to finish its internal navigation,
                // then check if the page is stable again.
                setTimeout(async () => {
                    try {
                        await client.pupPage.evaluate(() => true); // ping
                        clientReady = true;
                        console.log('✅ Page stable again — sends resumed.');
                    } catch (_) {
                        // Page is gone — full reconnect
                        console.log('🔄 Page unresponsive — reconnecting...');
                        try { await client.destroy(); } catch (_) {}
                        startClient();
                    }
                }, 8000);
            });
        }
    }, 10000);
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
// Passively caches every group message.
// Also forwards replies-to-order-messages back to Python.
// Uses message_create (fires for ALL messages incl. replies) instead of
// just 'message' (which can miss quoted replies in some WA versions).
// ─────────────────────────────────────────────
/**
 * Ask Gemini to classify a seller reply so the agent gets a useful summary.
 * Returns a short label + one-line summary, or null if Gemini is unavailable.
 */
async function classifyReplyWithGemini(sellerMessage, orderContext) {
    if (!GEMINI_API_KEY) return null;
    try {
        const prompt =
            `You are a logistics dispatch assistant. A seller in a WhatsApp group replied to a delivery update.\n\n` +
            `Order context: ${orderContext}\n` +
            `Seller reply: "${sellerMessage}"\n\n` +
            `Classify the reply into ONE of these categories:\n` +
            `QUESTION | COMPLAINT | CONFIRMED_AVAILABLE | RESCHEDULE_REQUEST | ADDRESS_CHANGE | OTHER\n\n` +
            `Then write one short sentence (max 15 words) summarising what the seller needs.\n` +
            `Reply in this exact format:\nCATEGORY: <category>\nSUMMARY: <summary>`;

        const resp = await axios.post(
            `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${GEMINI_API_KEY}`,
            { contents: [{ role: 'user', parts: [{ text: prompt }] }], generationConfig: { temperature: 0.1, maxOutputTokens: 100 } },
            { timeout: 8000 }
        );
        const text = resp.data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
        const category = (text.match(/CATEGORY:\s*(\w+)/) || [])[1] || 'OTHER';
        const summary  = (text.match(/SUMMARY:\s*(.+)/)   || [])[1] || sellerMessage.slice(0, 80);
        return { category, summary };
    } catch (e) {
        console.log('⚠️  Gemini classify failed:', e.message);
        return null;
    }
}

async function handleGroupMessage(msg) {
    // Resolve the chat ID — whatsapp-web.js puts it in different places
    // depending on the message direction and WA Web version.
    const chatId = msg.from || msg._data?.id?.remote || '';
    if (!chatId.includes(SAVED_GROUP_ID.split('@')[0])) {
        // Log unrecognised chats once so we can debug group ID mismatches
        if (chatId && !chatId.endsWith('@c.us')) {
            console.log(`📡 Message from unknown chat: ${chatId}`);
        }
        return;
    }

    const isFromMe = msg.fromMe || msg.id?.fromMe || false;
    if (isFromMe) return; // never process our own sent messages

    if (msg.body) cacheMessage(msg.id._serialized, msg.body);

    // Only act when seller explicitly quotes/replies to one of our updates
    if (!msg.hasQuotedMsg) return;

    try {
        const quoted = await msg.getQuotedMessage();

        // Match 1: quoted text contains "Order #N"
        let orderId = null;
        const ids = extractOrderIds(quoted.body || '');
        if (ids.length > 0) orderId = ids[0];

        // Match 2: reverse map — quoted message was sent by the bot for a delivery
        if (!orderId && msgToOrderId.has(quoted.id._serialized)) {
            orderId = msgToOrderId.get(quoted.id._serialized);
            console.log(`🔁 Reverse-mapped quoted msg → Delivery #${orderId}`);
        }

        if (!orderId) return; // not related to any known delivery

        // Use Gemini to classify and summarise the reply
        const det = orderDetails.get(orderId);
        const orderCtx = det
            ? `Delivery #${orderId}, Customer: ${det.customerName}, Items: ${det.items}`
            : `Delivery #${orderId}`;
        const ai = await classifyReplyWithGemini(msg.body, orderCtx);

        const comment = ai
            ? `[${ai.category}] ${ai.summary}\n\nOriginal: "${msg.body}"`
            : msg.body;

        console.log(`🔔 Seller reply on Delivery #${orderId}${ai ? ` [${ai.category}]` : ''} — notifying dashboard...`);

        const webhookRes = await axios.post(`${PYTHON_APP_URL}/api/whatsapp-webhook`, {
            order_id:     orderId,
            comment,
            sender_phone: msg.author || msg.from,
        }).catch(e => { console.log('⚠️  Webhook failed:', e.message); return null; });

        if (webhookRes) console.log(`✅ Dashboard notified (HTTP ${webhookRes.status})`);
    } catch (e) {
        console.log('Error processing quoted reply:', e.message);
    }
}

// Listen on both events: 'message' (received) + 'message_create' (all incl. replies)
// so we never miss a group reply regardless of WA Web version.
client.on('message',        handleGroupMessage);
client.on('message_create', handleGroupMessage);

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

    // Always refresh order details so reply matching works even without a cached message
    if (customerName || customerPhone || items) {
        orderDetails.set(cleanId, { customerName, customerPhone, items });
    }

    if (!clientReady) {
        console.log('⚠️  Client not ready yet — rejecting request.');
        return res.status(503).json({ success: false, error: 'WhatsApp client not ready. Try again in a moment.' });
    }

    // Guard: ping the Puppeteer page before any send attempt.
    // Catches detached-frame state before it causes an error mid-send.
    if (!await isPageAlive()) {
        console.log('⚠️  Page unresponsive — triggering reconnect.');
        clientReady = false;
        try { await client.destroy(); } catch (_) {}
        startClient();
        return res.status(503).json({ success: false, error: 'WhatsApp page restarting — try again in a moment.' });
    }

    // Deduplicate: if a send is already in progress for this order, wait for it
    // instead of firing a second identical message. Prevents button-spam doubles.
    if (sendQueue.has(cleanId)) {
        console.log(`⏳ Send already in progress for Order #${cleanId} — waiting...`);
        try {
            await sendQueue.get(cleanId);
            return res.status(200).json({ success: true, quoted: false, deduped: true });
        } catch (_) {
            return res.status(503).json({ success: false, error: 'Previous send failed' });
        }
    }

    let resolveSendQueue, rejectSendQueue;
    sendQueue.set(cleanId, new Promise((res, rej) => { resolveSendQueue = res; rejectSendQueue = rej; }));

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

        // Store sent message in history but do NOT update orderIdIndex and
        // mark as sent so findBestMatch never returns it as an original.
        if (sentMsg && sentMsg.id) {
            cacheMessage(sentMsg.id._serialized, message, false, true);
            // Reverse map: both the found original msg and the bot's reply
            // point back to this order so replies to either get routed correctly.
            if (cachedId) msgToOrderId.set(cachedId, cleanId);
            msgToOrderId.set(sentMsg.id._serialized, cleanId);
            saveCache();
        }

        resolveSendQueue();
        sendQueue.delete(cleanId);
        res.status(200).json({ success: true, quoted: !!cachedId });

    } catch (error) {
        console.error('❌ Send Error:', error.message);
        rejectSendQueue(error);
        sendQueue.delete(cleanId);

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
    clearChromeLocks();
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
