const express = require('express');
const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcode = require('qrcode-terminal');
const axios = require('axios');

console.log('🚀 Booting up Clawbot...');

const app = express();
app.use(express.json());

// --- CONFIGURATION ---
// 1. Once you see the ID in the logs, paste it here (e.g. "120363042123456789@g.us")
const SAVED_GROUP_ID = "PASTE_YOUR_ID_HERE_LATER"; 

// 2. Your Python Dashboard URL
const PYTHON_APP_URL = "https://inventory-production-d41e.up.railway.app";

const client = new Client({
    authStrategy: new LocalAuth(),
    puppeteer: { 
        args: ['--no-sandbox', '--disable-setuid-sandbox'],
        handleSIGINT: false,
        protocolTimeout: 0 
    }
});

// --- QR CODE STRATEGY ---
client.on('qr', (qr) => {
    console.log('\n=========================================================');
    console.log('🤖 SCAN THIS QR CODE TO LINK THE BOT:');
    qrcode.generate(qr, { small: true });
    console.log('\n⚠️ LINK FOR PERFECT IMAGE:');
    console.log(`https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=${encodeURIComponent(qr)}`);
    console.log('=========================================================\n');
});

client.on('ready', () => {
    console.log('✅ Clawbot is ONLINE and ready. No heavy sync needed.');
});

// --- THE LISTENER (Hear comments & find Group ID) ---
client.on('message', async (msg) => {
    const chat = await msg.getChat();
    
    // LOG EVERYTHING: This helps you find the ID for "BRO'S😎"
    if (chat.isGroup) {
        console.log(`🔍 Activity in Group: "${chat.name}" | ID: ${chat.id._serialized}`);
    }

    // Two-Way Sync: If someone replies to an order message
    if (msg.hasQuotedMsg) {
        try {
            const quotedMsg = await msg.getQuotedMessage();
            const orderMatch = quotedMsg.body.match(/Order\s?#(\d+)/i);
            
            if (orderMatch) {
                const orderId = orderMatch[1];
                console.log(`🔔 Found comment on Order #${orderId}. Notifying Python...`);

                await axios.post(`${PYTHON_APP_URL}/api/whatsapp-webhook`, {
                    order_id: orderId,
                    comment: msg.body,
                    sender_phone: msg.author || msg.from
                }).catch(e => console.log("⚠️ Python Webhook error (Check your Python URL/Route)"));
            }
        } catch (e) {
            console.log("Error processing quote:", e.message);
        }
    }
});

// --- THE SENDER (Triggered by your Dashboard) ---
app.post('/send-group-feedback', async (req, res) => {
    const { groupName, message, orderId } = req.body;
    console.log(`\n📥 Outbound Request for ${orderId}`);

    try {
        let groupId = SAVED_GROUP_ID;
        
        // Dynamic find if ID isn't hardcoded yet
        if (groupId === "PASTE_YOUR_ID_HERE_LATER") {
            const chats = await client.getChats();
            const target = chats.find(c => c.name === groupName);
            if (!target) return res.status(404).json({ error: "Group ID not found. Send a message to the group on your phone first." });
            groupId = target.id._serialized;
        }

        const chat = await client.getChatById(groupId);
        const messages = await chat.fetchMessages({ limit: 50 });
        
        // Search for the original message bubble to reply to
        const targetMsg = messages.reverse().find(m => m.body && m.body.includes(orderId));

        if (targetMsg) {
            console.log(`✅ Replying to original Order ${orderId} message.`);
            await targetMsg.reply(message);
        } else {
            console.log(`⚠️ Order ${orderId} not found in recent chat. Sending fresh message.`);
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
    console.log(`🤖 Clawbot API listening on port ${PORT}`);
});