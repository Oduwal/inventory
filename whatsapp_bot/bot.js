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
async function humanizedSend(jid, text, quotedKey, quotedBody) {
    await sock.sendPresenceUpdate('composing', jid);
    const ms = 2000 + Math.random() * 2000;
    await new Promise(r => setTimeout(r, ms));
    await sock.sendPresenceUpdate('paused', jid);

    const opts = {};
    // If caller supplies a quoted message key + body, construct the quote context
    // so the group sees which order update this is referencing.
    // participant is required for group messages — without it WhatsApp silently
    // drops the quote rendering even though the message still sends.
    if (quotedKey && quotedBody) {
        opts.quoted = {
            key: {
                remoteJid:   jid,
                fromMe:      true,
                id:          quotedKey,
                participant: sock.user?.id || sock.user?.jid || '',
            },
            message: { conversation: quotedBody },
        };
    }

    const result = await sock.sendMessage(jid, { text }, opts);
    return result.key.id;   // Baileys message ID — returned to Python for persistence
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

/** Extract the quoted stanza ID if the message is a reply */
function extractQuotedId(msg) {
    const m = msg.message;
    if (!m) return null;
    const ctx =
        m.extendedTextMessage?.contextInfo ||
        m.imageMessage?.contextInfo ||
        m.videoMessage?.contextInfo ||
        m.documentMessage?.contextInfo ||
        null;
    return ctx?.stanzaId || null;
}

const ORDER_REGEX = /Order\s*#?\s*(\d+)/gi;
function extractOrderIds(text) {
    if (!text) return [];
    return [...text.matchAll(ORDER_REGEX)].map(m => m[1]);
}

// ─────────────────────────────────────────────
// INBOUND HANDLER
// Flow:
//  A. Non-reply message with "Order #N" → tell Python to cache (msg_id → order_id)
//     so the bot can quote the ORIGINAL order post when agent sends an update.
//  B. Any reply (has a quoted message) → forward to Python.
//     Python looks up the quoted msg_id in whatsapp_outbound_map which contains
//     BOTH the original order posts (source='group') AND bot updates (source='bot').
//     So sellers can quote EITHER and it routes to the right delivery.
// ─────────────────────────────────────────────
async function handleInbound(msg) {
    const jid = msg.key.remoteJid || '';
    if (!jid.includes(GROUP_JID.split('@')[0])) return;
    if (msg.key.fromMe) return;

    const text     = extractText(msg);
    const quotedId = extractQuotedId(msg);
    const sender   = msg.key.participant || jid;
    const msgId    = msg.key.id;

    console.log(`📨 Group msg from ${sender.split('@')[0]}: "${text.slice(0, 80)}"`);

    // A — cache original order posts (non-replies that mention an order number)
    if (!quotedId && text) {
        const orderIds = extractOrderIds(text);
        for (const orderId of orderIds) {
            console.log(`📌 Caching original order post — Order #${orderId} msg_id=${msgId.slice(0,20)}`);
            axios.post(`${PYTHON_APP_URL}/api/cache-wa-message`, {
                message_id: msgId,
                order_id:   parseInt(orderId),
                body:       text,
                source:     'group',
            }, { timeout: 5000 }).catch(e => console.log('⚠️  Cache POST failed:', e.message));
        }
    }

    // B — forward any reply to Python regardless of what was quoted
    if (!quotedId) return;
    console.log(`🔁 Reply quoting ${quotedId.slice(0,20)}... — forwarding to Python`);
    axios.post(`${PYTHON_APP_URL}/api/whatsapp-webhook`, {
        quoted_message_id: quotedId,
        reply_text:        text,
        sender_phone:      sender,
    }, { timeout: 10000 }).catch(e => console.log('⚠️  Webhook POST failed:', e.message));
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
    const { orderId, message, quoteMessageId, quoteMessageBody } = req.body;

    if (!orderId || !message) {
        return res.status(400).json({ success: false, error: 'orderId and message are required' });
    }

    if (!clientReady || !sock) {
        return res.status(503).json({ success: false, error: 'Bot not ready — try again shortly.' });
    }

    console.log(`\n📤 Sending update for Order #${orderId}...`);

    try {
        const msgId = await humanizedSend(
            GROUP_JID,
            message,
            quoteMessageId   || null,
            quoteMessageBody || null,
        );
        console.log(`✅ Sent (msg_id: ${msgId?.slice(0, 20)}...)`);
        res.json({ success: true, message_id: msgId });
    } catch (e) {
        console.error('❌ Send error:', e.message);
        // If the connection dropped mid-send, trigger reconnect
        if (!clientReady) {
            setTimeout(connectToWhatsApp, 2000);
        }
        res.status(500).json({ success: false, error: e.message });
    }
});

// ─────────────────────────────────────────────
// BOOT
// ─────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🤖 API listening on port ${PORT}`);
});

connectToWhatsApp();
