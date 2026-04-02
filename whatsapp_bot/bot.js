const express = require('express');
const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcode = require('qrcode-terminal');
console.log('🚀 Booting up Clawbot...');

const app = express();
app.use(express.json());

// Memory cache to hold Group IDs for instant messaging
const groupCache = new Map();
let isCaching = false;

// Initialize the Clawbot (with infinite timeout to prevent crashes on large accounts)
const client = new Client({
    authStrategy: new LocalAuth(),
    puppeteer: { 
        args: ['--no-sandbox', '--disable-setuid-sandbox'],
        protocolTimeout: 9999999 // Disables the 3-minute crash limit
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
    
    // Build the cache in the background so API requests are INSTANT
    console.log('⏳ Pre-loading groups into memory... (This might take a few minutes on large accounts)');
    isCaching = true;
    try {
        const chats = await client.getChats();
        let groupCount = 0;
        for (const chat of chats) {
            if (chat.isGroup) {
                groupCache.set(chat.name, chat.id._serialized);
                groupCount++;
            }
        }
        console.log(`✅ Background sync complete! Loaded ${groupCount} groups into memory.`);
    } catch (err) {
        console.error('❌ Background sync failed. Try restarting the bot in Railway.', err);
    } finally {
        isCaching = false;
    }
});

// Our custom API endpoint that Python will call
app.post('/send-group-feedback', async (req, res) => {
    const { groupName, message } = req.body;
    console.log(`\n📥 Received request to message group: "${groupName}"`);

    // FAST PATH: If the group is already in memory, send instantly!
    if (groupCache.has(groupName)) {
        try {
            const groupId = groupCache.get(groupName);
            console.log(`✅ Found group "${groupName}" in memory! Sending message...`);
            await client.sendMessage(groupId, message);
            console.log(`🚀 Message dropped successfully!`);
            return res.status(200).json({ success: true, message: `Sent to ${groupName}` });
        } catch (error) {
            console.error('❌ Crash while sending message:', error);
            return res.status(500).json({ success: false, error: error.toString() });
        }
    }

    // If it's not in memory, check if the bot is still downloading history
    if (isCaching) {
        console.log(`⚠️ Bot is still syncing chats in the background. Rejecting request.`);
        return res.status(503).json({ success: false, error: "The bot is still syncing your WhatsApp chats. Please wait 2-3 minutes and try again." });
    }

    // If it's not in memory and downloading is finished, the group doesn't exist.
    console.log(`❌ Could not find a group named "${groupName}".`);
    return res.status(404).json({ success: false, error: `Group '${groupName}' not found. Make sure the name matches exactly.` });
}); 

client.initialize();

// Tell the bot to use Railway's assigned port, and listen on the internal network
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🤖 Clawbot API listening on port ${PORT}`);
});