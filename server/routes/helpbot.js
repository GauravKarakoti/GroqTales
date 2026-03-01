/**
 * Helpbot API Route
 * POST /api/helpbot/chat — MADHAVA help-bot powered by Groq LLM
 */

const express = require('express');
const router = express.Router();

/**
 * @swagger
 * /api/helpbot/chat:
 *   post:
 *     tags:
 *       - Helpbot
 *     summary: Chat with MADHAVA help bot
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               message:
 *                 type: string
 *               history:
 *                 type: array
 *                 items:
 *                   type: object
 *                   properties:
 *                     role:
 *                       type: string
 *                     content:
 *                       type: string
 *     responses:
 *       200:
 *         description: Bot reply
 */
router.post('/chat', async (req, res) => {
    try {
        const { message, history = [] } = req.body;

        if (!message || typeof message !== 'string') {
            return res.status(400).json({ error: 'A non-empty message string is required.' });
        }

        const GROQ_API_KEY = process.env.GROQ_API_KEY;

        // If no Groq key configured, return a helpful fallback
        if (!GROQ_API_KEY) {
            return res.json({
                reply:
                    "I'm MADHAVA, the GroqTales help bot. The AI backend is not configured yet, but I can tell you that GroqTales lets you create AI-generated stories and mint them as NFTs on the Monad blockchain! Check out /create to get started.",
            });
        }

        const systemPrompt = `You are MADHAVA, the helpful assistant for the GroqTales platform — an AI-powered Web3 storytelling platform where users create stories and mint them as NFTs on the Monad blockchain.

You help users with:
- Creating stories (text & comic)
- Minting NFTs from approved stories  
- Wallet setup (MetaMask, Coinbase, WalletConnect)
- Understanding genres, community features, and the moderation process
- Troubleshooting platform issues

Be friendly, concise, and helpful. Use markdown for formatting when useful. Keep answers under 200 words unless the user needs detailed instructions.`;

        const messages = [
            { role: 'system', content: systemPrompt },
            ...history.slice(-10), // keep last 10 messages for context
            { role: 'user', content: message },
        ];

        const groqRes = await fetch('https://api.groq.com/openai/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${GROQ_API_KEY}`,
            },
            body: JSON.stringify({
                model: 'llama-3.1-8b-instant',
                messages,
                max_tokens: 512,
                temperature: 0.7,
            }),
        });

        if (!groqRes.ok) {
            const errText = await groqRes.text();
            console.error('Groq API error:', groqRes.status, errText);
            return res.json({
                reply: "Sorry, I'm having trouble connecting to my AI brain right now. Please try again in a moment!",
            });
        }

        const groqData = await groqRes.json();
        const reply = groqData.choices?.[0]?.message?.content || "I couldn't generate a response. Please try again.";

        return res.json({ reply });
    } catch (error) {
        console.error('Helpbot error:', error);
        return res.status(500).json({
            reply: "Oops — something went wrong on my end. Please try again later.",
        });
    }
});

module.exports = router;
