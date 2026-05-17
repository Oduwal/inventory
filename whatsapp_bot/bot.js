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
    downloadMediaMessage,
} from '@whiskeysockets/baileys';
import P from 'pino';
import express from 'express';
import QRCode from 'qrcode';
import qrcode from 'qrcode-terminal';
import axios from 'axios';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import NodeCache from 'node-cache';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

console.log('🚀 Booting Clawbot (Baileys edition)...');

// ─────────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────────
const GROUP_JID      = process.env.WA_GROUP_ID    || '';
const PYTHON_APP_URL = process.env.PYTHON_APP_URL || 'https://atomics.up.railway.app';
const AUTH_DIR       = process.env.WA_AUTH_DIR    || path.join(__dirname, '.wwebjs_auth', 'baileys');
const WARMED_GROUPS_FILE = path.join(AUTH_DIR, 'warmed-groups.json');

// Set RESET_AUTH=true in Railway env vars to wipe session and re-scan QR.
// Remove the env var after scanning to avoid resetting on every deploy.
if (process.env.RESET_AUTH === 'true') {
    console.log('🗑️ RESET_AUTH=true — deleting auth session at', AUTH_DIR);
    fs.rmSync(AUTH_DIR, { recursive: true, force: true });
    console.log('✅ Auth session deleted. Will show new QR code.');
}
const PORT           = process.env.PORT            || 3000;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET  || '';

// Only process messages from these seller groups.
// Set WA_SELLER_GROUPS="group1@g.us,group2@g.us" in env to override.
// Check Railway logs for "NEW GROUP DETECTED" to discover new group IDs.
const SELLER_GROUPS = new Set(
    (process.env.WA_SELLER_GROUPS || '').split(',').map(s => s.trim()).filter(Boolean)
);

// ─────────────────────────────────────────────
// STATE
// ─────────────────────────────────────────────
let sock        = null;
let clientReady = false;
let latestQrUrl = null;   // pre-rendered data: URL for the /qr page
const contactNames = new Map(); // jid → push name (cached from messages & contacts events)
const groupParticipants = new Map(); // groupJid → Map(participantJid → { name, phone })

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────

/** Human-like delay — 2–4 seconds with typing presence */
async function humanizedSend(jid, text, quotedKey, quotedBody, quoteSender, quoteFromMe, mentions) {
    try {
        await sock.sendPresenceUpdate('composing', jid);
        const ms = 2000 + Math.random() * 2000;
        await new Promise(r => setTimeout(r, ms));
        await sock.sendPresenceUpdate('paused', jid);
    } catch (presenceErr) {
        console.log(`⚠️ Presence update failed (${presenceErr.message}) — sending message anyway`);
    }

    const opts = {};
    if (quotedKey && quotedBody) {
        // Use explicit sender ID if available, otherwise fall back to bot's own ID
        // so the quote still renders (WhatsApp needs some participant to show the quote)
        let participantId = quoteSender || sock.user?.id || sock.user?.jid || '';

        opts.quoted = {
            key: {
                remoteJid:   jid,
                fromMe:      quoteFromMe || !quoteSender,
                id:          quotedKey,
                // Only set participant if it looks like a valid JID — empty string crashes jidDecode
                ...(participantId && participantId.includes('@') ? { participant: participantId } : {}),
            },
            message: { conversation: quotedBody },
        };
        console.log(`   → quoting with participant: ${participantId}, fromMe: ${!quoteSender || quoteFromMe}`);
    }

    const msgPayload = { text };
    if (mentions && mentions.length > 0) {
        msgPayload.mentions = mentions;
    }

    // Retry up to 3 times — Baileys rc9 can throw "All connection attempts failed"
    // even when clientReady=true due to a WebSocket race condition.
    let lastErr;
    for (let attempt = 1; attempt <= 3; attempt++) {
        try {
            const result = await sock.sendMessage(jid, msgPayload, opts);
            return result.key.id;
        } catch (err) {
            lastErr = err;
            const isConnErr = err.message?.includes('connection') || err.message?.includes('Connection');
            if (isConnErr && attempt < 3) {
                console.log(`⚠️ Send attempt ${attempt} failed (${err.message}) — retrying in 3s...`);
                await new Promise(r => setTimeout(r, 3000));
            } else {
                throw err;
            }
        }
    }
    throw lastErr;
}

/** Extract plain text body from any Baileys message object */
function extractText(msg) {
    const m = msg.message;
    if (!m) {
        console.log(`⚠️ msg.message is NULL — keys on msg: ${Object.keys(msg).join(', ')}`);
        console.log(`⚠️ msg.messageStubType: ${msg.messageStubType}, msg.messageTimestamp: ${msg.messageTimestamp}`);
        return '';
    }

    // Debug: log the message keys so we can see what Baileys gives us
    console.log(`📋 Message keys: ${Object.keys(m).join(', ')}`);

    return (
        m.conversation ||
        m.extendedTextMessage?.text ||
        m.imageMessage?.caption ||
        m.videoMessage?.caption ||
        // Baileys sometimes nests the real message inside these wrappers
        m.ephemeralMessage?.message?.conversation ||
        m.ephemeralMessage?.message?.extendedTextMessage?.text ||
        m.viewOnceMessage?.message?.conversation ||
        m.viewOnceMessage?.message?.extendedTextMessage?.text ||
        m.documentWithCaptionMessage?.message?.documentMessage?.caption ||
        ''
    );
}

/** Replace @mention JIDs in text with contact names */
function resolveMentions(text, msg) {
    const m = msg.message;
    if (!m) return text;
    const ctx =
        m.extendedTextMessage?.contextInfo ||
        m.ephemeralMessage?.message?.extendedTextMessage?.contextInfo ||
        null;
    const mentioned = ctx?.mentionedJid || [];
    let resolved = text;
    for (const jid of mentioned) {
        const phone = jid.replace('@s.whatsapp.net', '').replace('@lid', '');
        const name = contactNames.get(jid) || '';
        if (name) {
            // Replace @phone with @name
            resolved = resolved.replace(new RegExp(`@${phone}\\b`, 'g'), `@${name}`);
        }
    }
    return resolved;
}

/** Extract quoted stanza ID AND the quoted message body */
function extractQuoted(msg) {
    const m = msg.message;
    if (!m) return { id: null, body: null };
    const ctx =
        m.extendedTextMessage?.contextInfo ||
        m.audioMessage?.contextInfo ||
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
                `You are reading a delivery order message from a Nigerian logistics WhatsApp group.\n\n` +
                `Message:\n"${text}"\n\n` +
                `RULES:\n` +
                `1. Extract the CUSTOMER name and CUSTOMER phone number.\n` +
                `2. The customer is the RECIPIENT of the delivery (not the sender/seller/dispatcher).\n` +
                `3. If the message has labeled fields like "Customer name:", "Name:", "Receiver:" — ALWAYS use that value as the name.\n` +
                `4. If there are labeled fields (like "Order number:", "Customer name:", "Phone number:") then the first line is the SENDER — do NOT use it as the customer name.\n` +
                `5. If there are NO labeled fields (just plain text with a name, address, phone), then the first line may be the customer name — use your judgment.\n` +
                `6. "Phone number:" or "Whatsapp number:" fields contain the customer's phone.\n` +
                `7. Return digits only for phone (no spaces, dashes, or +).\n\n` +
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
// Warm up Signal sessions with every participant of a freshly-onboarded seller
// group so the FIRST real message decrypts cleanly. Without this, the bot has
// no 1:1 session with new participants → their first sender-key distribution
// fails → that first order message is lost. assertSessions is invisible to
// participants (no DM, no notification — protocol-level key exchange only).
const _warmedGroups = new Set();
const _warmingNow   = new Set();
try {
    if (fs.existsSync(WARMED_GROUPS_FILE)) {
        for (const j of JSON.parse(fs.readFileSync(WARMED_GROUPS_FILE, 'utf8'))) {
            _warmedGroups.add(j);
        }
    }
} catch (_) {}

function persistWarmedGroups() {
    try {
        fs.writeFileSync(WARMED_GROUPS_FILE, JSON.stringify([..._warmedGroups]));
    } catch (e) {
        console.log('⚠️  Could not persist warmed-groups file:', e.message);
    }
}

async function warmUpGroup(jid) {
    if (_warmedGroups.has(jid) || _warmingNow.has(jid)) return;
    _warmingNow.add(jid);
    try {
        console.log(`🔥 Warming up sessions for new seller group: ${jid}`);
        const meta = await sock.groupMetadata(jid);
        const participants = (meta?.participants || []).map(p => p.id).filter(Boolean);
        if (!participants.length) {
            console.log(`⚠️  No participants found for ${jid} — skipping warm-up`);
            return;
        }
        // assertSessions establishes 1:1 Signal sessions in batches.
        // Baileys handles concurrency internally; we just await the call.
        await sock.assertSessions(participants, true);
        _warmedGroups.add(jid);
        persistWarmedGroups();
        console.log(`✅ Warm-up complete for ${jid} (${participants.length} participants)`);
    } catch (e) {
        console.log(`⚠️  Warm-up failed for ${jid}: ${e.message}`);
    } finally {
        _warmingNow.delete(jid);
    }
}

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

    // First time we see this seller group, kick off a session warm-up in the
    // background so subsequent messages decrypt without retry-recovery delays.
    if (!_warmedGroups.has(jid) && !_warmingNow.has(jid)) {
        warmUpGroup(jid);  // intentionally not awaited — runs in background
    }
    if (msg.key.fromMe) {
        console.log(`⏭️ Skipping own message (fromMe=true)`);
        return;
    }

    const rawText               = extractText(msg);
    const text                  = resolveMentions(rawText, msg);
    const { id: quotedId,
            body: quotedBody }  = extractQuoted(msg);
    const sender                = msg.key.participant || jid;
    const msgId                 = msg.key.id;

    // Detect voice note (audioMessage with ptt=true)
    let audioB64 = '';
    let audioMime = '';
    const m = msg.message || {};
    const audioMsg = m.audioMessage
        || m.ephemeralMessage?.message?.audioMessage
        || m.viewOnceMessage?.message?.audioMessage;
    if (audioMsg && audioMsg.ptt) {
        try {
            console.log(`🎤 Voice note detected — downloading...`);
            const buffer = await downloadMediaMessage(msg, 'buffer', {}, {
                logger: P({ level: 'silent' }),
                reuploadRequest: sock.updateMediaMessage,
            });
            audioB64 = buffer.toString('base64');
            audioMime = audioMsg.mimetype || 'audio/ogg; codecs=opus';
            console.log(`🎤 Voice note downloaded: ${buffer.length} bytes, mime: ${audioMime}`);
        } catch (dlErr) {
            console.log(`⚠️ Failed to download voice note: ${dlErr.message}`);
        }
    }

    if (!text && !audioB64) return;
    const _pushName = msg.pushName || '';
    console.log(`📨 Group msg from ${sender.split('@')[0]} (pushName: "${_pushName}"): "${(text || '[Voice Note]').slice(0, 80)}"`);

    // Treat the message as a fresh order even when it quotes something, if it
    // contains order-shaped fields. Sellers often quote a promo blast when
    // submitting a real customer order — the quote is decoration, not a reply.
    const _looksLikeOrder = !!text && (
        /name\s*[:：]/i.test(text) ||
        /phone\s*(number)?\s*[:：]/i.test(text) ||
        /\baddress\s*[:：]/i.test(text) ||
        /^\s*(SR|UGB|AR|UL|AGH)\b/i.test(text)
    );

    if (quotedId && !_looksLikeOrder) {
        console.log(`🔁 Reply quoting ${quotedId.slice(0, 20)}... — forwarding to Python`);
        const senderName = msg.pushName || contactNames.get(sender) || '';
        axios.post(`${PYTHON_APP_URL}/api/whatsapp-webhook`, {
            quoted_message_id:   quotedId,
            quoted_message_body: quotedBody || '',
            reply_text:          text,
            sender_phone:        sender,
            sender_name:         senderName,
            groupJid:            jid,
            audio_b64:           audioB64,
            audio_mime:          audioMime,
        }, {
            timeout: 30000,
            headers: WEBHOOK_SECRET ? { 'x-webhook-secret': WEBHOOK_SECRET } : {},
        }).catch(e => console.log('⚠️  Webhook POST failed:', e.message));
        return;
    }

    if (quotedId && _looksLikeOrder) {
        console.log(`📨 Quote-decorated fresh order detected — ignoring quote, routing to fresh path`);
    }

    // Voice-only messages without a quote — still cache if they have text with customer info
    if (!text) {
        console.log(`🎤 Voice note without quote or text — skipping cache`);
        return;
    }

    const senderName = msg.pushName || contactNames.get(sender) || '';

    // Forward fresh group messages to /api/whatsapp-webhook so the Python
    // app can auto-create orders from well-formed posts. Gated on the Python
    // side by SELLER_GROUP_BRANCH_MAP + the supervisor toggle.
    axios.post(`${PYTHON_APP_URL}/api/whatsapp-webhook`, {
        quoted_message_id:   '',
        quoted_message_body: '',
        reply_text:          text,
        sender_phone:        sender,
        sender_name:         senderName,
        groupJid:            jid,
        message_id:          msgId,
        audio_b64:           '',
        audio_mime:          '',
    }, {
        timeout: 30000,
        headers: WEBHOOK_SECRET ? { 'x-webhook-secret': WEBHOOK_SECRET } : {},
    }).catch(e => console.log('⚠️  Fresh-message webhook POST failed:', e.message));

    // Keep the existing cache-wa-message path so dashboard-created orders
    // can still be matched against incoming group posts.
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
        sender_name:     senderName,
        customer_name:   info.customer_name,
        customer_phone:  info.customer_phone,
        groupJid:        jid,
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

    // In-memory message store so getMessage() can return originals for retries.
    // LID groups need this — without it, Baileys can't recover from "No session
    // found to decrypt message" failures.
    const recentMessages = new NodeCache({ stdTTL: 600, useClones: false });
    const msgRetryCounterCache = new NodeCache({ stdTTL: 60, useClones: false });
    const placeholderResendCache = new NodeCache({ stdTTL: 60, useClones: false });

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
        // Recovery path for LID-mode group decryption failures. When a retry
        // exceeds count 1 and enableAutoSessionRecreation is on, Baileys deletes
        // the broken Signal session and forces a fresh key exchange — fixing
        // "No session found to decrypt message" without a manual re-pair.
        enableAutoSessionRecreation: true,
        enableRecentMessageCache: true,
        msgRetryCounterCache,
        placeholderResendCache,
        maxMsgRetryCount: 5,
        retryRequestDelayMs: 250,
        getMessage: async (key) => {
            const cached = recentMessages.get(`${key.remoteJid}:${key.id}`);
            return cached || { conversation: '' };
        },
    });

    // Cache outgoing/incoming message bodies so getMessage can serve retries.
    sock.ev.on('messages.upsert', ({ messages }) => {
        for (const m of messages) {
            if (m.key?.id && m.message) {
                recentMessages.set(`${m.key.remoteJid}:${m.key.id}`, m.message);
            }
            // Harvest LID↔PN mappings — workaround for issue #2263 where
            // lid-mapping.update doesn't fire reliably in 7.0.0-rc.9.
            const p  = m.key?.participant;
            const pa = m.key?.participantAlt;
            if (p && pa && sock.signalRepository?.lidMapping) {
                try {
                    if (p.endsWith('@lid') && pa.endsWith('@s.whatsapp.net')) {
                        sock.signalRepository.lidMapping.storeLIDPNMapping(p, pa);
                    } else if (p.endsWith('@s.whatsapp.net') && pa.endsWith('@lid')) {
                        sock.signalRepository.lidMapping.storeLIDPNMapping(pa, p);
                    }
                } catch (_) {}
            }
        }
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
            // Pre-warm sessions for every configured seller group in parallel
            // so the FIRST message after a fresh deploy / new-group add decrypts
            // cleanly. Already-warmed groups are skipped via the persisted set.
            const groupsToWarm = [...SELLER_GROUPS].filter(j => !_warmedGroups.has(j));
            if (groupsToWarm.length > 0) {
                console.log(`🔥 Pre-warming ${groupsToWarm.length} seller group(s) on connect...`);
                Promise.all(groupsToWarm.map(j => warmUpGroup(j)))
                    .catch(e => console.log('⚠️  Pre-warm batch error:', e.message));
            }
        }
    });

    // Cache contact names from contacts sync
    sock.ev.on('contacts.upsert', (contacts) => {
        for (const c of contacts) {
            const name = c.notify || c.verifiedName || c.name || '';
            if (name) contactNames.set(c.id, name);
        }
        console.log(`📇 Cached ${contactNames.size} contact names`);
    });

    sock.ev.on('contacts.update', (updates) => {
        for (const c of updates) {
            const name = c.notify || c.verifiedName || c.name || '';
            if (name) contactNames.set(c.id, name);
        }
    });

    // Map @lid participant IDs to @s.whatsapp.net IDs for name resolution
    // Baileys fires this with the mapping between lid and regular JIDs
    sock.ev.on('messaging-history.set', ({ contacts }) => {
        if (contacts) {
            for (const c of contacts) {
                const name = c.notify || c.verifiedName || c.name || '';
                if (name && c.id) contactNames.set(c.id, name);
                if (name && c.lidJid) contactNames.set(c.lidJid, name);
            }
            console.log(`📇 History sync: ${contactNames.size} contact names cached`);
        }
    });

    sock.ev.on('messages.upsert', async ({ messages, type }) => {
        if (type !== 'notify') return;
        for (const msg of messages) {
            // Cache push name from incoming messages — store under both JID formats
            const sender = msg.key.participant || msg.key.remoteJid || '';
            const pushName = msg.pushName || '';
            const groupJid = msg.key.remoteJid || '';
            const phone = sender.replace('@s.whatsapp.net', '').replace('@lid', '');

            if (sender && pushName) {
                contactNames.set(sender, pushName);
                // Cross-cache: @lid ↔ @s.whatsapp.net
                if (sender.endsWith('@s.whatsapp.net')) contactNames.set(phone + '@lid', pushName);
                if (sender.endsWith('@lid')) contactNames.set(phone + '@s.whatsapp.net', pushName);
            }

            // Always track group participants (even without pushName — shows phone at minimum)
            if (sender && (groupJid.endsWith('@g.us') || groupJid.endsWith('@lid'))) {
                if (!groupParticipants.has(groupJid)) groupParticipants.set(groupJid, new Map());
                const existing = groupParticipants.get(groupJid).get(sender);
                const name = pushName || (existing ? existing.name : '');
                groupParticipants.get(groupJid).set(sender, { name, phone });
            }

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
app.use(express.json({ limit: '10mb' }));

// Middleware: require x-api-key header on operational routes
const BOT_API_KEY = process.env.BOT_API_KEY || '';
function requireApiKey(req, res, next) {
    if (!BOT_API_KEY) {
        console.warn('⚠️  BOT_API_KEY not set — operational routes are unprotected!');
        return next();
    }
    if (req.headers['x-api-key'] !== BOT_API_KEY) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
}

// QR code page — requires ?token=<QR_TOKEN> to prevent public access
app.get('/qr', async (req, res) => {
    const expected = process.env.QR_TOKEN || '';
    if (!expected || req.query.token !== expected) {
        res.set('WWW-Authenticate', 'Bearer realm="qr"');
        return res.status(401).send('<h2 style="font-family:sans-serif;color:red">401 Unauthorized — missing or invalid token.</h2>');
    }
    if (clientReady) {
        return res.send('<h2 style="font-family:sans-serif;color:green">✅ Already authenticated — no QR needed.</h2>');
    }
    if (!latestQrUrl) {
        return res.send('<h2 style="font-family:sans-serif;color:orange">⏳ QR not ready yet — refresh in a few seconds.</h2>');
    }
    res.send(`<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Clawbot QR</title><meta http-equiv="refresh" content="30;url=/qr?token=${encodeURIComponent(expected)}">
<style>body{font-family:sans-serif;text-align:center;padding:40px;background:#111;color:#eee;}
img{border:12px solid #fff;border-radius:12px;}</style></head>
<body><h2>📱 Scan with WhatsApp</h2>
<p style="color:#aaa;font-size:13px;">Auto-refreshes every 30s</p>
<img src="${latestQrUrl}" alt="QR Code"/></body></html>`);
});

// Health check — used by the Python dashboard to monitor a fleet of bots.
const _bootedAt = Date.now();
app.get('/health', (_req, res) => {
    res.json({
        status: clientReady ? 'ok' : 'degraded',
        waConnected: clientReady,
        botPhone: process.env.BOT_PHONE || '',
        sellerGroups: [...SELLER_GROUPS],
        warmedGroups: [..._warmedGroups],
        warmingNow: [..._warmingNow],
        uptimeSec: Math.floor((Date.now() - _bootedAt) / 1000),
        version: '2.0.0',
    });
});

/**
 * GET /group-participants?jid=120363...@g.us
 * Returns list of group members with name and JID.
 */
app.get('/group-participants', requireApiKey, async (req, res) => {
    const jid = req.query.jid;
    if (!jid) return res.status(400).json({ error: 'jid query param required' });
    if (!clientReady || !sock) return res.status(503).json({ error: 'Bot not connected' });

    try {
        const metadata = await sock.groupMetadata(jid);
        // Try to resolve names: check @lid ID, @s.whatsapp.net ID, and group metadata
        const participants = metadata.participants.map(p => {
            const phone = p.id.replace('@s.whatsapp.net', '').replace('@lid', '');
            const altJid = p.id.endsWith('@lid')
                ? phone + '@s.whatsapp.net'
                : phone + '@lid';
            const name = contactNames.get(p.id)
                || contactNames.get(altJid)
                || p.notify || p.vname || p.name || '';
            if (name) {
                contactNames.set(p.id, name);
                contactNames.set(altJid, name);
            }
            return { jid: p.id, phone, name, admin: p.admin || null };
        });
        res.json({ group: metadata.subject, participants });
    } catch (e) {
        console.log('⚠️ groupMetadata failed:', e.message, '— using cached participants');
        // Fallback: return participants seen from messages in this group
        const cached = groupParticipants.get(jid);
        console.log(`📇 Cached participants for ${jid}: ${cached ? cached.size : 0} members`);
        if (cached) {
            for (const [pid, info] of cached.entries()) {
                console.log(`   → ${pid} = "${info.name}" (${info.phone})`);
            }
        }
        if (cached && cached.size > 0) {
            const participants = Array.from(cached.entries()).map(([pid, info]) => ({
                jid: pid,
                phone: info.phone,
                name: info.name || '',
                admin: null,
            }));
            res.json({ group: 'Seller Group', participants });
        } else {
            res.json({ group: '', participants: [] });
        }
    }
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
app.post('/send-group-feedback', requireApiKey, async (req, res) => {
    const { orderId, message, quoteMessageId, quoteMessageBody, quoteMessageSender, quoteMessageFromMe, targetGroupJid, mentions } = req.body;

    if (!orderId || !message) {
        return res.status(400).json({ success: false, error: 'orderId and message are required' });
    }

    if (!clientReady || !sock) {
        return res.status(503).json({ success: false, error: 'Bot not ready — try again shortly.' });
    }

    console.log(`\n📤 Sending update for Order #${orderId}...`);
    console.log(`   → group: ${targetGroupJid || GROUP_JID || 'NONE'}`);
    console.log(`   → quoteId: ${quoteMessageId || 'NONE'}`);
    console.log(`   → quoteSender: ${quoteMessageSender || 'NONE'}`);
    console.log(`   → quoteBody: ${(quoteMessageBody || '').slice(0, 50) || 'NONE'}`);
    console.log(`   → mentions: ${JSON.stringify(mentions || [])}`);

    try {
        const msgId = await humanizedSend(
            targetGroupJid || GROUP_JID,
            message,
            quoteMessageId   || null,
            quoteMessageBody || null,
            quoteMessageSender || null,
            quoteMessageFromMe || false,
            mentions           || []
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

/**
 * POST /send-group-voice
 * Body (JSON):
 *   orderId          string  — delivery ID (for logging)
 *   audioBase64      string  — base64-encoded audio (OGG/Opus)
 *   targetGroupJid?  string  — group to send to
 *   quoteMessageId?  string  — Baileys ID to quote
 *   quoteMessageBody? string — body of quoted message
 *   quoteMessageSender? string — JID of original sender
 *
 * Response: { success, message_id }
 */
app.post('/send-group-voice', requireApiKey, async (req, res) => {
    const { orderId, audioBase64, targetGroupJid, quoteMessageId, quoteMessageBody, quoteMessageSender, quoteMessageFromMe } = req.body;

    if (!orderId || !audioBase64) {
        return res.status(400).json({ success: false, error: 'orderId and audioBase64 are required' });
    }

    if (!clientReady || !sock) {
        return res.status(503).json({ success: false, error: 'Bot not ready — try again shortly.' });
    }

    console.log(`\n🎤 Sending voice note for Order #${orderId}...`);
    console.log(`   → group: ${targetGroupJid || GROUP_JID || 'NONE'}`);

    try {
        const audioBuffer = Buffer.from(audioBase64, 'base64');
        const jid = targetGroupJid || GROUP_JID;

        // Typing indicator
        try {
            await sock.sendPresenceUpdate('recording', jid);
            const ms = 1000 + Math.random() * 1500;
            await new Promise(r => setTimeout(r, ms));
            await sock.sendPresenceUpdate('paused', jid);
        } catch (presenceErr) {
            console.log(`⚠️ Presence update failed: ${presenceErr.message}`);
        }

        // Build quote options if present
        const opts = {};
        if (quoteMessageId && quoteMessageBody) {
            let participantId = quoteMessageSender || sock.user?.id || '';
            opts.quoted = {
                key: {
                    remoteJid:   jid,
                    fromMe:      quoteMessageFromMe || !quoteMessageSender,
                    id:          quoteMessageId,
                    participant: participantId,
                },
                message: { conversation: quoteMessageBody },
            };
        }

        const result = await sock.sendMessage(jid, {
            audio: audioBuffer,
            ptt: true,
            mimetype: 'audio/ogg; codecs=opus',
        }, opts);

        const msgId = result.key.id;
        console.log(`✅ Voice note sent (msg_id: ${msgId?.slice(0, 20)}...)`);
        res.json({ success: true, message_id: msgId });
    } catch (e) {
        console.error('❌ Voice send error:', e.message);
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
