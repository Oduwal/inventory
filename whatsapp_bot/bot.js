const express = require('express');
const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcode = require('qrcode-terminal');
console.log('🚀 Booting up Clawbot...');

const app = express();
app.use(express.json());

// Initialize the Clawbot (Uses LocalAuth to remember your session so you only scan the QR once)
const client = new Client({
    authStrategy: new LocalAuth(),
    puppeteer: { args: ['--no-sandbox', '--disable-setuid-sandbox'] }
});

// Generate QR Code for the Admin to scan
client.on('qr', (qr) => {
    console.log('\n=========================================================');
    console.log('🤖 SCAN THIS QR CODE TO LINK THE BOT:');
    
    // Print the terminal version
    qrcode.generate(qr, { small: true });
    
    // Print a clickable web link for a perfect image
    console.log('\n⚠️ IF THE TERMINAL CODE ABOVE DOES NOT SCAN, CLICK THIS LINK FOR A PERFECT IMAGE:');
    console.log(`https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=${encodeURIComponent(qr)}`);
    console.log('=========================================================\n');
});

client.on('ready', () => {
    console.log('✅ Clawbot is online and linked to WhatsApp!');
});

// Our custom API endpoint that Python will call
app.post('/send-group-feedback', async (req, res) => {
    const { groupName, message } = req.body;
    console.log(`\n📥 Received request to message group: "${groupName}"`);

    try {
        console.log('⏳ Fetching WhatsApp chats... (this might take a few seconds)');
        const chats = await client.getChats();
        console.log(`✅ Loaded ${chats.length} chats. Searching for target group...`);

        const targetGroup = chats.find(chat => chat.isGroup && chat.name === groupName);

        if (targetGroup) {
            console.log(`✅ Found group "${groupName}"! Sending message...`);
            await client.sendMessage(targetGroup.id._serialized, message);
            console.log(`🚀 Message dropped successfully!`);
            res.status(200).json({ success: true, message: `Sent to ${groupName}` });
        } else {
            console.log(`❌ Could not find a group named "${groupName}".`);
            res.status(404).json({ success: false, error: "Group not found. Make sure the bot's phone is in the group and the name is an exact match." });
        }
    } catch (error) {
        console.error('❌ Crash while sending message:', error);
        res.status(500).json({ success: false, error: error.toString() });
    }
}); // <-- This is the closing tag that was likely missing!

client.initialize();

// Tell the bot to use Railway's assigned port, and listen on the internal network
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🤖 Clawbot API listening on port ${PORT}`);
});