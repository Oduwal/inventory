const express = require('express');
const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcode = require('qrcode-terminal');

const app = express();
app.use(express.json());

// Initialize the Clawbot (Uses LocalAuth to remember your session so you only scan the QR once)
const client = new Client({
    authStrategy: new LocalAuth(),
    puppeteer: { args: ['--no-sandbox', '--disable-setuid-sandbox'] }
});

// Generate QR Code for the Admin to scan in the terminal
client.on('qr', (qr) => {
    console.log('\n=========================================================');
    console.log('SCAN THIS QR CODE WITH YOUR WHATSAPP TO LINK THE BOT:');
    console.log('=========================================================\n');
    qrcode.generate(qr, { small: true });
});

client.on('ready', () => {
    console.log('✅ Clawbot is online and linked to WhatsApp!');
});

// Our custom API endpoint that Python will call
app.post('/send-group-feedback', async (req, res) => {
    const { groupName, message } = req.body;

    try {
        // Fetch all your WhatsApp chats to find the right group
        const chats = await client.getChats();
        const targetGroup = chats.find(chat => chat.isGroup && chat.name === groupName);

        if (targetGroup) {
            await client.sendMessage(targetGroup.id._serialized, message);
            res.status(200).json({ success: true, message: `Sent to ${groupName}` });
        } else {
            res.status(404).json({ success: false, error: "Group not found. Ensure the bot's phone is in this group." });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: error.toString() });
    }
}); // <-- This is the closing tag that was likely missing!

client.initialize();

app.listen(3000, () => {
    console.log('🤖 Clawbot API listening on port 3000');
});