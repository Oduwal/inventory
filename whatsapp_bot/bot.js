const express = require('express');
const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcode = require('qrcode-terminal');
const axios = require('axios');

console.log('🚀 Booting up Clawbot (Production Mode)...');

const app = express();
app.use(express.json());

// --- FINAL CONFIGURATION ---
// 1. Your exact Group ID:
const SAVED_GROUP_ID = "120363239510350827@g.us"; 

// 2. Your Python Dashboard URL:
const PYTHON_APP_URL = "https://inventory-production-d41e.up.railway.app";

// Initialize with advanced memory protection for Railway
const client = new Client({
    authStrategy: new LocalAuth(),
    puppeteer: { 
        headless: true,
        args: [
            '--no-sandbox', 
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage', // ⬅️ Prevents the silent crash!
            '--disable-accelerated-2d-canvas',
            '--no-first-run',
            '--no-zygote',
            '--disable-gpu'
        ],
        handleSIGINT: false,
        protocolTimeout: 0 
    }
});

// --- QR CODE & STATUS ---
client.on('qr', (qr) => {
    console.log('🤖 SCAN QR CODE:');
    qrcode.generate(qr, { small: true });
});

client.on('ready', () => {
    console.log('✅ CLAWBOT IS ONLINE AND LOCKED ONTO YOUR GROUP!');
});

client.on('disconnected', (reason) => {
    console.log('❌ WhatsApp Disconnected!', reason);
});

// --- TWO-WAY SYNC (Listener) ---
client.on('message', async (msg) => {
    // If someone replies to an Order message in the group
    if (msg.hasQuotedMsg) {
        try {
            const quotedMsg = await msg.getQuotedMessage();
            const orderMatch = quotedMsg.body.match(/Order\s?#(\d+)/i);
            
            if (orderMatch) {
                const orderId = orderMatch[1];
                console.log(`🔔 Order #${orderId} comment found! Notifying Agent Dashboard...`);
                
                await axios.post(`${PYTHON_APP_URL}/api/whatsapp-webhook`, {
                    order_id: orderId,
                    comment: msg.body,
                    sender_phone: msg.author || msg.from
                }).catch(e => console.log("⚠️ Failed to reach Python App. Is the URL correct?"));
            }
        } catch (e) {
            console.log("Error processing quote:", e.message);
        }
    }
});

// --- THE SENDER (Python -> WhatsApp) ---
app.post('/send-group-feedback', async (req, res) => {
    const { groupName, message, orderId } = req.body;
    console.log(`\n📥 Sending update for ${orderId}...`);

    try {
        const chat = await client.getChatById(SAVED_GROUP_ID);
        
        // Look for the original message to reply to
        const messages = await chat.fetchMessages({ limit: 50 });
        const targetMsg = messages.reverse().find(m => m.body && m.body.includes(orderId));

        if (targetMsg) {
            await targetMsg.reply(message);
            console.log(`✅ Replying to original ${orderId} message.`);
        } else {
            await client.sendMessage(SAVED_GROUP_ID, message);
            console.log(`✅ Dropping fresh message for ${orderId}.`);
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