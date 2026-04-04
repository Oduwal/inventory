// ─────────────────────────────────────────────────────────────────────────────
// CLAWBOT — WhatsApp Group Notifier
// Runtime: Node.js ESM  |  Library: @whiskeysockets/baileys
//
// Stateless design:
//   • Bot sends messages, returns the Baileys message_id to Python.
//   • Python persists (message_id → order_id) in whatsapp_outbound_map.
//   • On inbound reply the bot just extracts quoted stanzaId and POSTs it
//     to Python — no in-memory maps needed, survives restarts cleanly.
// ─────────────────────────────────────────────────────────────────────────────

import makeWASocket, {
    useMultiFileAuthState,
    DisconnectReason,
    fetchLatestBaileysVersion,
    makeCacheableSignalKeyStore,
    Browsers,
} from '@whiskeysockets/baileys';
import P from 'pino';
import express from 'express';
import QRCode from 'qrcode';
import qrcode from 'qrcode-terminal';
import axios from 'axios';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

console.log('🚀 Booting Clawbot (Baileys edition)...');

// ─────────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────────
const GROUP_JID      = process.env.WA_GROUP_ID    || '120363239510350827@g.us';
const PYTHON_APP_URL = process.env.PYTHON_APP_URL || 'https://inventory-production-d41e.up.railway.app';
const AUTH_DIR       = process.env.WA_AUTH_DIR    || path.join(__dirname, '.wwebjs_auth', 'baileys');
const PORT           = process.env.PORT            || 3000;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET  || '';

// Only process messages from these seller groups.
// Set WA_SELLER_GROUPS="group1@g.us,group2@g.us" in env to override.
// Check Railway logs for "NEW GROUP DETECTED" to discover new group IDs.
const SELLER_GROUPS = new Set(
    (process.env.WA_SELLER_GROUPS || [
        '120363418850903362@g.us',  // DAGGO
        '120363304493232977@g.us',  // NEXTILE
        '120363287198677451@g.us',  // NEWLIFE
        '120363239510350827@g.us',  // LOCO
    ].join(',')).split(',').map(s => s.trim()).filter(Boolean)
);

// ─────────────────────────────────────────────
// STATE
// ─────────────────────────────────────────────
let sock        = null;
let clientReady = false;
let latestQrUrl = null;   // pre-rendered data: URL for the /qr page

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────

/** Human-like delay — 2–4 seconds with typing presence */
async function humanizedSend(jid, text, quotedKey, quotedBody, quoteSender, quoteFromMe) {
    await sock.sendPresenceUpdate('composing', jid);
    const ms = 2000 + Math.random() * 2000;
    await new Promise(r => setTimeout(r, ms));
    await sock.sendPresenceUpdate('paused', jid);

    const opts = {};
    if (quotedKey && quotedBody) {
        // STRICT PARTICIPANT LOGIC:
        // If it's from the group (seller), we MUST use their explicit quoteSender ID.
        // We only fall back to the Bot's ID if quoteFromMe is explicitly true.
        let participantId = quoteSender;
        if (!participantId) {
            participantId = quoteFromMe ? (sock.user?.id || sock.user?.jid || '') : '';
        }

        opts.quoted = {
            key: {
                remoteJid:   jid,
                fromMe:      quoteFromMe || false,
                id:          quotedKey,
                participant: participantId,
            },
            message: { conversation: quotedBody },
        };
    }

    const result = await sock.sendMessage(jid, { text }, opts);
    return result.key.id;
}

/** Extract plain text body from any Baileys message object */
function extractText(msg) {
    const m = msg.message;
    if (!m) return '';
    return (
        m.conversation ||
        m.extendedTextMessage?.text ||
        m.imageMessage?.caption ||
        m.videoMessage?.caption ||
        ''
    );
}

/** Extract quoted stanza ID AND the quoted message body */
function extractQuoted(msg) {
    const m = msg.message;
    if (!m) return { id: null, body: null };
    const ctx =
        m.extendedTextMessage?.contextInfo ||
        m.imageMessage?.contextInfo ||
        m.videoMessage?.contextInfo ||
        m.documentMessage?.contextInfo ||
        null;
    if (!ctx) return { id: null, body: null };
    const quotedMsg = ctx.quotedMessage;
    const body = quotedMsg
        ? (quotedMsg.conversation ||
           quotedMsg.extendedTextMessage?.text ||
           quotedMsg.imageMessage?.caption ||
           quotedMsg.videoMessage?.caption || '')
        : '';
    return { id: ctx.stanzaId || null, body };
}

const GEMINI_KEY = process.env.GEMINI_API_KEY || '';
const GEMINI_URL = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent';

/**
 * Extract customer name and phone from a group message.
 * Primary: Gemini AI (handles any format/language).
 * Fallback: regex — catches Nigerian phone numbers and the line before/after them as name.
 * This ensures matching works even without GEMINI_API_KEY on the bot service.
 */
async function extractCustomerInfo(text) {
    // ── Gemini path ────────────────────────────────────────────────────────
    if (GEMINI_KEY) {
        try {
            const prompt =
                `You are reading a message from a Nigerian logistics WhatsApp group. ` +
                `The message is a delivery order posted by a seller or dispatcher.\n\n` +
                `Message:\n"${text}"\n\n` +
                `Extract the CUSTOMER name and CUSTOMER phone number from this message. ` +
                `The customer is the person receiving the delivery (not the sender/seller). ` +
                `Reply ONLY with valid JSON, no markdown:\n` +
                `{"customer_name": "<name or null>", "customer_phone": "<digits only or null>"}`;

            const resp = await axios.post(
                `${GEMINI_URL}?key=${GEMINI_KEY}`,
                { contents: [{ role: 'user', parts: [{ text: prompt }] }],
                  generationConfig: { temperature: 0, maxOutputTokens: 1064 } },
                { timeout: 6000 }
            );
            const raw   = resp.data?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || '{}';
            const clean = raw.startsWith('```') ? raw.replace(/```[a-z]*\n?/g, '').trim() : raw;
            const result = JSON.parse(clean);
            if (result.customer_name || result.customer_phone) {
                console.log(`🤖 Gemini → name:"${result.customer_name}" phone:"${result.customer_phone}"`);
                return result;
            }
        } catch (e) {
            console.log('⚠️  Gemini extract failed:', e.message, '— falling back to regex');
        }
    }

    // ── Regex fallback — works without GEMINI_API_KEY ──────────────────────
    // Nigerian phones: 07x, 08x, 09x, +234, 0-803 etc. (10-11 digits)
    const phoneMatch = text.match(/(?:\+?234|0)[\s\-]?[789]\d[\s\-]?\d{3,4}[\s\-]?\d{3,4}/);
    const customer_phone = phoneMatch ? phoneMatch[0].replace(/\D/g, '') : null;

    // Name heuristic: first non-empty line that looks like a name
    // (2+ words, mostly letters, not a label like "Phone:", "Address:")
    const SKIP = /^(phone|address|item|product|qty|quantity|note|location|area|delivery|order|price|amount|date)/i;
    let customer_name = null;
    for (const line of text.split(/\n|\r/)) {
        const t = line.trim();
        if (!t || SKIP.test(t)) continue;
        const words = t.split(/\s+/).filter(w => /^[A-Za-z'-]{2,}$/.test(w));
        if (words.length >= 2) { customer_name = t; break; }
    }

    console.log(`🔍 Regex → name:"${customer_name}" phone:"${customer_phone}"`);
    return { customer_name, customer_phone };
}

// ─────────────────────────────────────────────
// INBOUND HANDLER
// Flow:
//  A. Non-reply group message → Gemini extracts customer name/phone → Python matches
//     against its delivery database and stores (message_id → order_id, source='group').
//     This is the "original order post" the bot will quote when agents send updates.
//
//  B. Reply (has a quoted message) → forward to Python.
//     Python does O(1) lookup by quoted message_id — works whether the seller quoted
//     the original post OR a bot update, since both are in whatsapp_outbound_map.
// ─────────────────────────────────────────────
async function handleInbound(msg) {
    const jid = msg.key.remoteJid || '';

    // Log EVERY group/lid message so you can discover new IDs in Railway logs
    if (jid.endsWith('@g.us') || jid.endsWith('@lid')) {
        console.log(`\n🎯 GROUP MESSAGE FROM: ${jid}\n`);
    }

    // Only process messages from known seller groups — ignore personal chats,
    // family groups, etc. so they don't pollute the pending cache or match wrong orders.
    if (!SELLER_GROUPS.has(jid)) {
        if (!jid.includes('status@broadcast') && (jid.endsWith('@g.us') || jid.endsWith('@lid'))) {
            console.log(`🆕 NEW GROUP DETECTED: ${jid} — add to WA_SELLER_GROUPS env var if this is a seller group`);
        }
        return;
    }
    if (msg.key.fromMe) return;

    const text                  = extractText(msg);
    const { id: quotedId,
            body: quotedBody }  = extractQuoted(msg);
    const sender                = msg.key.participant || jid;
    const msgId                 = msg.key.id;

    if (!text) return;
    console.log(`📨 Group msg from ${sender.split('@')[0]}: "${text.slice(0, 80)}"`);

    if (quotedId) {
        console.log(`🔁 Reply quoting ${quotedId.slice(0, 20)}... — forwarding to Python`);
        axios.post(`${PYTHON_APP_URL}/api/whatsapp-webhook`, {
            quoted_message_id:   quotedId,
            quoted_message_body: quotedBody || '',
            reply_text:          text,
            sender_phone:        sender,
            groupJid:            jid,
        }, {
            timeout: 10000,
            headers: WEBHOOK_SECRET ? { 'x-webhook-secret': WEBHOOK_SECRET } : {},
        }).catch(e => console.log('⚠️  Webhook POST failed:', e.message));
        return;
    }

    const info = await extractCustomerInfo(text);
    if (!info.customer_name && !info.customer_phone) {
        console.log(`📭 No customer info found — skipping cache`);
        return;
    }
    console.log(`🤖 Gemini extracted → name:"${info.customer_name}" phone:"${info.customer_phone}" — sending to Python`);
    axios.post(`${PYTHON_APP_URL}/api/cache-wa-message`, {
        message_id:      msgId,
        body:            text,
        sender:          sender,
        customer_name:   info.customer_name,
        customer_phone:  info.customer_phone,
        groupJid:        jid,   // already normalised @lid → @g.us above
    }, {
        timeout: 8000,
        headers: WEBHOOK_SECRET ? { 'x-webhook-secret': WEBHOOK_SECRET } : {},
    }).then(() => console.log(`✅ Cached order → Python (group: ${jid.slice(0,20)}...)`)).catch(e => console.log('⚠️  Cache POST failed:', e.message));
}

// ─────────────────────────────────────────────
// BAILEYS CONNECTION
// ─────────────────────────────────────────────
async function connectToWhatsApp() {
    fs.mkdirSync(AUTH_DIR, { recursive: true });

    const { state, saveCreds } = await useMultiFileAuthState(AUTH_DIR);
    const { version }          = await fetchLatestBaileysVersion();

    sock = makeWASocket({
        version,
        auth: {
            creds: state.creds,
            keys:  makeCacheableSignalKeyStore(state.keys, P({ level: 'silent' })),
        },
        printQRInTerminal: false,
        logger:            P({ level: 'warn' }),
        browser:           Browsers.ubuntu('Chrome'),
        generateHighQualityLinkPreview: false,
        syncFullHistory: false,
    });

    sock.ev.on('creds.update', saveCreds);

    sock.ev.on('connection.update', async (update) => {
        const { connection, lastDisconnect, qr } = update;

        if (qr) {
            try {
                latestQrUrl = await QRCode.toDataURL(qr, { scale: 8 });
            } catch (_) {}
            const host = process.env.RAILWAY_PUBLIC_DOMAIN
                ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`
                : `http://localhost:${PORT}`;
            console.log(`🤖 SCAN QR CODE → ${host}/qr`);
            qrcode.generate(qr, { small: true });
        }

        if (connection === 'close') {
            clientReady = false;
            latestQrUrl = null;
            const code  = (lastDisconnect?.error)?.output?.statusCode;
            const loggedOut = code === DisconnectReason.loggedOut;
            console.log(`❌ Disconnected (code ${code}) — ${loggedOut ? 'logged out' : 'reconnecting...'}`);
            if (!loggedOut) {
                // Exponential backoff: max 30s
                const attempt = (connectToWhatsApp._attempt = (connectToWhatsApp._attempt || 0) + 1);
                const wait = Math.min(attempt * 5000, 30000);
                console.log(`⏳ Reconnect in ${wait / 1000}s (attempt ${attempt})...`);
                setTimeout(connectToWhatsApp, wait);
            } else {
                console.log('🔑 Delete auth directory and restart to re-scan QR.');
            }
        } else if (connection === 'open') {
            connectToWhatsApp._attempt = 0;
            clientReady = true;
            latestQrUrl = null;
            console.log('✅ CLAWBOT IS ONLINE AND LOCKED ONTO YOUR GROUP!');
        }
    });

    sock.ev.on('messages.upsert', async ({ messages, type }) => {
        if (type !== 'notify') return;
        for (const msg of messages) {
            try {
                await handleInbound(msg);
            } catch (e) {
                console.log('❌ handleInbound error:', e.message);
            }
        }
    });
}

// ─────────────────────────────────────────────
// EXPRESS API
// ─────────────────────────────────────────────
const app = express();
app.use(express.json());

// QR code page — auto-refreshes every 30s
app.get('/qr', async (_req, res) => {
    if (clientReady) {
        return res.send('<h2 style="font-family:sans-serif;color:green">✅ Already authenticated — no QR needed.</h2>');
    }
    if (!latestQrUrl) {
        return res.send('<h2 style="font-family:sans-serif;color:orange">⏳ QR not ready yet — refresh in a few seconds.</h2>');
    }
    res.send(`<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Clawbot QR</title><meta http-equiv="refresh" content="30">
<style>body{font-family:sans-serif;text-align:center;padding:40px;background:#111;color:#eee;}
img{border:12px solid #fff;border-radius:12px;}</style></head>
<body><h2>📱 Scan with WhatsApp</h2>
<p style="color:#aaa;font-size:13px;">Auto-refreshes every 30s</p>
<img src="${latestQrUrl}" alt="QR Code"/></body></html>`);
});

// Health check
app.get('/health', (_req, res) => {
    res.json({ status: 'ok', waConnected: clientReady });
});

/**
 * POST /send-group-feedback
 * Body (JSON):
 *   orderId          string  — delivery ID (for logging)
 *   message          string  — text to send
 *   quoteMessageId?  string  — Baileys ID of the ORIGINAL group order post to quote
 *   quoteMessageBody? string — body of that original post (needed by Baileys to build quote)
 *
 * Response: { success, message_id }
 * Python stores the returned message_id → orderId in whatsapp_outbound_map (source='bot').
 */
app.post('/send-group-feedback', async (req, res) => {
    const { orderId, message, quoteMessageId, quoteMessageBody, quoteMessageSender, quoteMessageFromMe, targetGroupJid } = req.body;

    if (!orderId || !message) {
        return res.status(400).json({ success: false, error: 'orderId and message are required' });
    }

    if (!clientReady || !sock) {
        return res.status(503).json({ success: false, error: 'Bot not ready — try again shortly.' });
    }

    console.log(`\n📤 Sending update for Order #${orderId}...`);

    try {
        const msgId = await humanizedSend(
            targetGroupJid || GROUP_JID,
            message,
            quoteMessageId   || null,
            quoteMessageBody || null,
            quoteMessageSender || null,
            quoteMessageFromMe || false
        );
        console.log(`✅ Sent (msg_id: ${msgId?.slice(0, 20)}...)`);
        res.json({ success: true, message_id: msgId });
    } catch (e) {
        console.error('❌ Send error:', e.message);
        if (!clientReady) {
            setTimeout(connectToWhatsApp, 2000);
        }
        res.status(500).json({ success: false, error: e.message });
    }
});

// ─────────────────────────────────────────────
// BOOT
// ─────────────────────────────────────────────
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`🤖 API listening on port ${PORT}`);
});

connectToWhatsApp();

// Graceful shutdown safety net to prevent Bad MAC errors
const exitHandler = () => {
    console.log('🛑 Railway shutting down... saving WhatsApp session safely.');
    if (sock) {
        sock.ws?.close(); // Safely closing websocket flushes current memory states to file
    }
    server.close(() => {
        console.log('✅ Server closed. Exiting process safely.');
        process.exit(0);
    });
    // Fallback: forcefully turn off if it is taking too long
    setTimeout(() => {
        console.log('⚠️ Forced shutdown after 5s.');
        process.exit(1);
    }, 5000);
};

// Listen for Railway shut down signals
process.on('SIGINT', exitHandler);
process.on('SIGTERM', exitHandler);
