const express = require('express');
const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcode = require('qrcode-terminal');
const axios = require('axios'); // For sending data back to Python

console.log('🚀 Booting up Clawbot...');

const app = express();
app.use(express.json());

// Memory cache to hold Group IDs for instant messaging
const groupCache = new Map();
let isCaching = false;

// Initialize the Clawbot
const client = new Client({
    authStrategy: new LocalAuth(),
    puppeteer: { 
        args: ['--no-sandbox', '--disable-setuid-sandbox'],
        protocolTimeout: 9999999 
    }
});

// Generate QR Code for the Admin to scan
client.on('qr', (qr) => {
    console.log('\n=========================================================');
    console.log('🤖 SCAN THIS QR CODE TO LINK THE BOT:');
    qrcode.generate(qr, { small: true });
    console.log('\n⚠️ IF THE TERMINAL CODE ABOVE DOES NOT SCAN, CLICK THIS LINK FOR A PERFECT IMAGE:');
    console.log(`https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=${encodeURIComponent(qr)}`);
    console.log('=========================================================\n');
});

// When the bot successfully logs in
client.on('ready', async () => {
    console.log('✅ Clawbot is online and linked to WhatsApp!');
    
    isCaching = true;
    try {
        console.log('⏳ Performing Targeted Sync for high-priority groups...');
        const chats = await client.getChats();
        
        // 1. Prioritize the top 40 most recent chats (where your active group is)
        const priorityLimit = Math.min(chats.length, 40);
        for (let i = 0; i < priorityLimit; i++) {
            const chat = chats[i];
            if (chat.isGroup) {
                groupCache.set(chat.name, chat.id._serialized);
                console.log(`🎯 Priority Group Cached: "${chat.name}"`);
            }
        }

        console.log(`✅ Priority sync complete! Recent groups are now "Fast Path".`);
        isCaching = false; // Unlock the API for the main groups immediately

        // 2. Quietly load the rest of the archive in the background
        if (chats.length > priorityLimit) {
            console.log(`📦 Background syncing remaining ${chats.length - priorityLimit} chats...`);
            for (let i = priorityLimit; i < chats.length; i++) {
                const chat = chats[i];
                if (chat.isGroup) {
                    groupCache.set(chat.name, chat.id._serialized);
                }
            }
            console.log(`🏁 Full history sync finished.`);
        }
    } catch (err) {
        console.error('❌ Sync failed:', err);
        isCaching = false;
    }
});

// NEW: Listener for incoming comments/tags in the group
client.on('message', async (msg) => {
    if (msg.hasQuotedMsg) {
        try {
            const quotedMsg = await msg.getQuotedMessage();
            // Regex to find "Order #123" or "Order#123"
            const orderMatch = quotedMsg.body.match(/Order\s?#(\d+)/i);
            
            if (orderMatch) {
                const orderId = orderMatch[1];
                const sender = msg.author || msg.from;
                const comment = msg.body;

                console.log(`\n🔔 New comment on Order #${orderId} from ${sender}: "${comment}"`);

                // Send to Python Webhook (Update this URL to your Python Railway Public URL)
                await axios.post("https://inventory-production-d41e.up.railway.app/api/whatsapp-webhook", {
                    order_id: orderId,
                    comment: comment,
                    sender_phone: sender
                }).catch(e => console.log("Python Webhook not ready yet."));
            }
        } catch (e) {
            console.log("Error processing quote:", e.message);
        }
    }
});

// API endpoint for Python to trigger replies
app.post('/send-group-feedback', async (req, res) => {
    const { groupName, message, orderId } = req.body;
    console.log(`\n📥 Request: "${groupName}" | Ref: ${orderId}`);

    const handleSend = async (groupId) => {
        const chat = await client.getChatById(groupId);
        const recentMessages = await chat.fetchMessages({ limit: 50 });
        
        let targetMessage = null;
        for (let i = recentMessages.length - 1; i >= 0; i--) {
            if (recentMessages[i].body && recentMessages[i].body.includes(orderId)) {
                targetMessage = recentMessages[i];
                break;
            }
        }

        if (targetMessage) {
            console.log(`✅ Quoting original message for ${orderId}`);
            await targetMessage.reply(message);
        } else {
            console.log(`⚠️ No original message found. Sending fresh message.`);
            await client.sendMessage(groupId, message);
        }
    };

    if (groupCache.has(groupName)) {
        try {
            await handleSend(groupCache.get(groupName));
            return res.status(200).json({ success: true });
        } catch (error) {
            return res.status(500).json({ success: false, error: error.toString() });
        }
    }

    if (isCaching) return res.status(503).json({ success: false, error: "Syncing..." });

    // Final Fallback: Live check
    try {
        const chats = await client.getChats();
        const target = chats.find(c => c.isGroup && c.name === groupName);
        if (target) {
            groupCache.set(groupName, target.id._serialized);
            await handleSend(target.id._serialized);
            return res.status(200).json({ success: true });
        }
        res.status(404).json({ success: false, error: "Group not found" });
    } catch (e) {
        res.status(500).json({ success: false, error: e.toString() });
    }
});

client.initialize();

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🤖 Clawbot API listening on port ${PORT}`);
});