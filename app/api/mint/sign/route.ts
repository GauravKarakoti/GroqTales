import { NextRequest, NextResponse } from 'next/server';
import { mintRequestSchema } from '@/lib/schemas';
import { ethers } from 'ethers';
import { headers } from 'next/headers';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import { prisma } from '@/lib/db';

const ADMIN_PRIVATE_KEY = process.env.ADMIN_PRIVATE_KEY;

function logAudit(event: string, status: 'SUCCESS' | 'FAILURE', details: Record<string, any>) {
  console.log(JSON.stringify({
    timestamp: new Date().toISOString(),
    event,
    status,
    ...details
  }));
}

export async function POST(req: NextRequest) {
  const headerStore = await headers();
  const ip = headerStore.get("x-forwarded-for") ?? "unknown";

  try {
    if (!ADMIN_PRIVATE_KEY) {
      console.error("CRITICAL: ADMIN_PRIVATE_KEY is missing");
      return NextResponse.json({ error: "Server configuration error" }, { status: 500 });
    }
    
    if (!ADMIN_PRIVATE_KEY.startsWith("0x") || ADMIN_PRIVATE_KEY.length !== 66) {
      console.error("CRITICAL: ADMIN_PRIVATE_KEY is invalid (must be 0x-prefixed hex)");
      return NextResponse.json({ error: "Server key configuration error" }, { status: 500 });
    }

    const session = await getServerSession(authOptions);
    if (!session) {
      logAudit('MINT_SIGNATURE_REQUEST', 'FAILURE', { reason: "Unauthorized", ip });
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    let body;
    try {
      body = await req.json();
    } catch (e) {
      logAudit('MINT_SIGNATURE_REQUEST', 'FAILURE', { reason: "Invalid JSON Body", ip });
      return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
    }

    const parseResult = mintRequestSchema.safeParse(body);
    if (!parseResult.success) {
      logAudit('MINT_SIGNATURE_REQUEST', 'FAILURE', { 
        reason: "Invalid Input Schema", 
        errors: parseResult.error.flatten(),
        ip 
      });
      return NextResponse.json({ error: parseResult.error.flatten() }, { status: 400 });
    }

    const { userWallet, storyId } = parseResult.data;

    const story = await prisma.story.findUnique({
      where: { id: storyId },
      select: { id: true, isMinted: true, authorWallet: true }
    });

    if (!story) {
      return NextResponse.json({ error: "Story not found" }, { status: 404 });
    }

    if (story.isMinted) {
      return NextResponse.json({ error: "Story already minted" }, { status: 403 });
    }

    if (story.authorWallet && story.authorWallet.toLowerCase() !== userWallet.toLowerCase()) {
      return NextResponse.json({ error: "Wallet mismatch" }, { status: 403 });
    }

    const wallet = new ethers.Wallet(ADMIN_PRIVATE_KEY);
    
    const messageHash = ethers.solidityPackedKeccak256(
      ["address", "string"], 
      [userWallet, storyId]
    );
    
    const signature = await wallet.signMessage(ethers.getBytes(messageHash));

    logAudit('MINT_SIGNATURE_GENERATED', 'SUCCESS', { userWallet, storyId, ip });
    
    return NextResponse.json({ 
      signature, 
      userWallet, 
      storyId 
    });

  } catch (error) {
    console.error("Mint Signing Critical Error:", error);
    
    logAudit('MINT_SIGNATURE_REQUEST', 'FAILURE', { 
      reason: "Critical Exception", 
      error: error instanceof Error ? error.message : "Unknown",
      ip 
    });

    return NextResponse.json({ error: "Internal processing failed" }, { status: 500 });
  }
}