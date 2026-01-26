import dbConnect from '@/lib/dbConnect';
import Outbox from '../models/Outbox';
import MintIntent from '../models/MintIntent';
import Story from '../models/Story';
import { mintNFT, checkTxStatus } from '@/lib/blockchain';

const MAX_RETRIES = 5;

async function processOutbox() {
  await dbConnect();
  
  const event = await Outbox.findOneAndUpdate(
    { status: 'pending' },
    { status: 'processing', processedAt: new Date() },
    { sort: { createdAt: 1 } }
  );

  if (!event) return;

  try {
    if (event.eventType === 'MintRequested') {
      await handleMintSaga(event);
    }
    
    await Outbox.updateOne({ _id: event._id }, { status: 'completed' });
  
  } catch (err: any) {
    console.error(`Failed to process event ${event._id}`, err);
    
    const attempts = (event.attempts ?? 0) + 1;
    const status = attempts >= MAX_RETRIES ? 'failed' : 'pending';
     
    await Outbox.updateOne({ _id: event._id }, { 
      status, 
      attempts, 
      lastError: err?.message 
    });
  }
}

async function handleMintSaga(event: any) {
  const { storyId, authorWallet, metadataUri } = event.payload;
  const intentId = `mint_${storyId}`;

  let intent = await MintIntent.findOne({ intentId });
  if (!intent) {
    intent = await MintIntent.create({
      intentId,
      storyId,
      status: 'pending'
    });
  }

  if (intent.status === 'pending') {
    const txHash = await mintNFT(authorWallet, metadataUri);
    
    intent.txHash = txHash;
    intent.status = 'submitted';
    await intent.save();
  }

  if (intent.status === 'submitted') {
    const receipt = await checkTxStatus(intent.txHash);
    
    if (receipt.status === 'confirmed') {
      intent.status = 'confirmed';
      intent.tokenId = receipt.tokenId;
      await intent.save();

      await Story.updateOne(
        { _id: storyId },
        { 
          status: 'minted', 
          nftTokenId: intent.tokenId,
          nftTxHash: intent.txHash 
        }
      );
    } else if (receipt.status === 'reverted') {
      throw new Error('Transaction reverted on chain');
    }
  }
}

setInterval(processOutbox, 2000);