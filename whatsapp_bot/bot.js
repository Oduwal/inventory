const express = require('express');
const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcode = require('qrcode-terminal');
const axios = require('axios');

const app = express();
app.use(express.json());

// --- CONFIGURATION ---
// 1. Paste your Group ID here once you see it in the logs (e.g. "120363042123456789@g.us")
const SAVED_GROUP_ID = "PASTE_YOUR_ID_HERE_LATER"; 

// 2. YOUR SPECIFIC PYTHON URL:
const PYTHON_APP_URL = "https://inventory-production-d41e.up.railway.app";

const client = new Client({
    authStrategy: new LocalAuth(),
    puppeteer: { 
        headless: true,
        args: [
            '--no-sandbox', 
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage', // ⬅️ THIS IS THE MAGIC BULLET FOR RAILWAY
            '--disable-accelerated-2d-canvas', // ⬅️ Turns off heavy graphics
            '--no-first-run',
            '--no-zygote',
            '--disable-gpu' // ⬅️ No GPU in Railway containers anyway
        ],
        handleSIGINT: false,
        protocolTimeout: 0 
    }
});

// --- ADD THESE NEW LISTENERS RIGHT BELOW IT ---
// These will act as alarms if the connection drops in the background!
client.on('disconnected', (reason) => {
    console.log('❌ WhatsApp Disconnected!', reason);
});

client.on('auth_failure', msg => {
    console.error('❌ Authentication failed!', msg);
});

client.on('qr', (qr) => {
    console.log('🤖 SCAN QR CODE:');
    qrcode.generate(qr, { small: true });
});

client.on('ready', () => {
    console.log('✅ CLAWBOT IS READY AND LISTENING FOR MESSAGES!');
});

// --- THE AGGRESSIVE ID FINDER ---
// This triggers for EVERY message (sent or received) to help us find that ID
client.on('message_create', async (msg) => {
    try {
        const chat = await msg.getChat();
        
        // This block prints the ID to your Railway logs every time you text the group
        console.log(`------------------------------------------`);
        console.log(`📩 ACTIVITY DETECTED!`);
        console.log(`👥 From Group/Chat: "${chat.name}"`);
        console.log(`🆔 ID: ${chat.id._serialized}`);
        console.log(`💬 Message: ${msg.body}`);
        console.log(`------------------------------------------`);

        // Two-Way Sync: If it's a reply to an Order message, tell Python
        if (msg.hasQuotedMsg) {
            const quotedMsg = await msg.getQuotedMessage();
            const orderMatch = quotedMsg.body.match(/Order\s?#(\d+)/i);
            
            if (orderMatch) {
                const orderId = orderMatch[1];
                console.log(`🔔 Order #${orderId} comment found! Notifying Python...`);
                
                await axios.post(`${PYTHON_APP_URL}/api/whatsapp-webhook`, {
                    order_id: orderId,
                    comment: msg.body,
                    sender_phone: msg.author || msg.from
                }).catch(e => console.log("⚠️ Python Webhook error - check if /api/whatsapp-webhook exists in main.py"));
            }
        }
    } catch (e) {
        console.log("Debug Error:", e.message);
    }
});

// --- THE SENDER (Python Dashboard -> Bot) ---
app.post('/send-group-feedback', async (req, res) => {
    const { groupName, message, orderId } = req.body;
    console.log(`\n📥 Request received for ${orderId}`);

    try {
        let groupId = SAVED_GROUP_ID;
        
        // If we haven't hardcoded the ID yet, try to find it by name
        if (groupId === "PASTE_YOUR_ID_HERE_LATER") {
            const chats = await client.getChats();
            const target = chats.find(c => c.name === groupName);
            if (!target) return res.status(404).json({ error: "Group not found. Send a text to it on your phone first." });
            groupId = target.id._serialized;
        }

        const chat = await client.getChatById(groupId);
        
        // Reply logic: find the original message and quote it
        const messages = await chat.fetchMessages({ limit: 50 });
        const targetMsg = messages.reverse().find(m => m.body && m.body.includes(orderId));

        if (targetMsg) {
            await targetMsg.reply(message);
        } else {
            await client.sendMessage(groupId, message);
        }
        
        res.status(200).json({ success: true });
    } catch (error) {
        console.error("❌ Send Error:", error);
        res.status(500).json({ success: false, error: error.message });
    }
});

client.initialize();

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🤖 API listening on port ${PORT}`);
});