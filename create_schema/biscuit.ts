/* eslint-disable no-use-before-define */
import * as ed from "@noble/ed25519";
import { randomBytes } from "crypto";

// ---- Helpers ---------------------------------------------------------------

export const bytesToHex = (b: Uint8Array) => Buffer.from(b).toString("hex");
export const hexToBytes = (hex: string) =>
  new Uint8Array(Buffer.from(hex, "hex"));

// Mirror of `schema::public_key::Algorithm::Ed25519 as i32` (little-endian)
const ED25519_ALG_ID = 0; // adjust if your schema uses a different value
function leI32(n: number): Uint8Array {
  const buf = Buffer.alloc(4);
  buf.writeInt32LE(n, 0);
  return new Uint8Array(buf);
}

// ---- Keys ------------------------------------------------------------------

/** PrivateKey: 32-byte secret scalar */
export class PrivateKey {
  constructor(public readonly bytes: Uint8Array) {
    if (bytes.length !== 32) throw new Error("Invalid PrivateKey size");
  }

  static generate(): PrivateKey {
    return new PrivateKey(ed.utils.randomPrivateKey());
  }

  static fromBytes(bytes: Uint8Array): PrivateKey {
    return new PrivateKey(new Uint8Array(bytes));
  }
  static fromHex(hex: string): PrivateKey {
    return new PrivateKey(hexToBytes(hex));
  }

  toBytes(): Uint8Array {
    return new Uint8Array(this.bytes);
  }
  toHex(): string {
    return bytesToHex(this.bytes);
  }

  public(): PublicKey {
    return new PublicKey(ed.getPublicKey(this.bytes));
  }
}

/** PublicKey: 32-byte Ed25519 public key */
export class PublicKey {
  constructor(public readonly bytes: Uint8Array) {
    if (bytes.length !== 32) throw new Error("Invalid PublicKey size");
  }

  static fromBytes(bytes: Uint8Array): PublicKey {
    return new PublicKey(new Uint8Array(bytes));
  }
  static fromHex(hex: string): PublicKey {
    return new PublicKey(hexToBytes(hex));
  }

  toBytes(): Uint8Array {
    return new Uint8Array(this.bytes);
  }
  toHex(): string {
    return bytesToHex(this.bytes);
  }

  toString(): string {
    return `ed25519/${this.toHex()}`;
  }
}

/** KeyPair wrapper */
export class KeyPair {
  constructor(public readonly priv: PrivateKey) {}
  static new(): KeyPair {
    return new KeyPair(PrivateKey.generate());
  }
  static fromPrivate(priv: PrivateKey): KeyPair {
    return new KeyPair(priv);
  }
  public(): PublicKey {
    return this.priv.public();
  }
  private(): PrivateKey {
    return this.priv;
  }
}

// ---- Signatures ------------------------------------------------------------

export type Signature = Uint8Array; // 64 bytes

/**
 * Sign like the Rust `sign()`: concat message || alg_id(LE i32) || next_pubkey
 * and Ed25519-sign that buffer.
 */
export async function sign(
  keypair: KeyPair,
  nextKey: KeyPair,
  message: Uint8Array
): Promise<Signature> {
  const toSign = concat(
    message,
    leI32(ED25519_ALG_ID),
    nextKey.public().toBytes()
  );
  return await ed.sign(toSign, keypair.private().toBytes());
}

/**
 * Verify a single block signature. If `external_signature` is present,
 * it’s validated against (block.data || alg_id || current_pubkey).
 */
export async function verifyBlockSignature(
  block: Block,
  currentPublicKey: PublicKey
): Promise<void> {
  // main signature over: data || alg_id || block.next_key
  let toVerify = concat(
    block.data,
    leI32(ED25519_ALG_ID),
    block.next_key.toBytes()
  );
  if (
    !(await ed.verify(block.signature, toVerify, currentPublicKey.toBytes()))
  ) {
    throw new Error("Invalid block signature");
  }

  if (block.external_signature) {
    // external sig over: data || alg_id || current_pubkey
    const extMsg = concat(
      block.data,
      leI32(ED25519_ALG_ID),
      currentPublicKey.toBytes()
    );
    const ok = await ed.verify(
      block.external_signature.signature,
      extMsg,
      block.external_signature.public_key.toBytes()
    );
    if (!ok) throw new Error("Invalid external signature");
  }
}

// ---- Token & Blocks --------------------------------------------------------

export class ExternalSignature {
  constructor(
    public readonly public_key: PublicKey,
    public readonly signature: Signature
  ) {}
}

export class Block {
  constructor(
    public readonly data: Uint8Array,
    public readonly next_key: PublicKey,
    public readonly signature: Signature,
    public readonly external_signature?: ExternalSignature | null
  ) {}
}

export class Token {
  constructor(
    public readonly root: PublicKey,
    public readonly blocks: Block[],
    public readonly next: TokenNext
  ) {}

  static async create(
    rootKey: KeyPair,
    nextKey: KeyPair,
    message: Uint8Array
  ): Promise<Token> {
    const signature = await sign(rootKey, nextKey, message);
    const block = new Block(message, nextKey.public(), signature, null);
    return new Token(rootKey.public(), [block], makeSecret(nextKey.private()));
  }

  async append(
    nextKey: KeyPair,
    message: Uint8Array,
    externalSig?: ExternalSignature | null
  ): Promise<Token> {
    const currKeypair = keypairOf(this.next); // throws if sealed
    const signature = await sign(currKeypair, nextKey, message);
    const block = new Block(
      message,
      nextKey.public(),
      signature,
      externalSig || null
    );
    return new Token(
      this.root,
      [...this.blocks, block],
      makeSecret(nextKey.private())
    );
  }

  async verify(root: PublicKey): Promise<void> {
    let currentPub = root;

    for (const block of this.blocks) {
      await verifyBlockSignature(block, currentPub);
      currentPub = block.next_key;
    }

    if (this.next.kind === "secret") {
      const lastPub = this.next.privateKey.public();
      if (!eqBytes(currentPub.toBytes(), lastPub.toBytes())) {
        throw new Error("Last public key does not match the private key");
      }
    } else {
      // Seal: verify over concat(data || next_key) for each block
      let buf = new Uint8Array(0);
      for (const b of this.blocks) {
        buf = concat(buf, b.data, b.next_key.toBytes());
      }
      const ok = await ed.verify(
        this.next.signature,
        buf,
        currentPub.toBytes()
      );
      if (!ok) throw new Error("Invalid final seal signature");
    }
  }
}

export namespace TokenNext {
  export class Secret {
    public readonly kind = "secret" as const;
    constructor(public readonly private_: PrivateKey) {}
    keypair(): KeyPair {
      return KeyPair.fromPrivate(this.private_);
    }
    get private(): PrivateKey {
      return this.private_;
    }
  }
  export class Seal {
    public readonly kind = "seal" as const;
    constructor(public readonly signature: Signature) {}
  }
}

// ---- TokenNext (discriminated union) --------------------------------------
export type TokenNext =
  | { kind: "secret"; privateKey: PrivateKey }
  | { kind: "seal"; signature: Signature };

export function makeSecret(privateKey: PrivateKey): TokenNext {
  return { kind: "secret", privateKey };
}
export function makeSeal(signature: Signature): TokenNext {
  return { kind: "seal", signature };
}

export function isSealed(next: TokenNext): boolean {
  return next.kind === "seal";
}

export function keypairOf(next: TokenNext): KeyPair {
  if (next.kind === "seal") throw new Error("Already sealed");
  return KeyPair.fromPrivate(next.privateKey);
}

// ---- Utils -----------------------------------------------------------------

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}
function eqBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// ---- Demo ------------------------------------------------------------------
// Run this file directly with ts-node to see it in action.
if (require.main === module) {
  (async () => {
    const root = KeyPair.new();
    const k2 = KeyPair.new();
    const msg1 = new Uint8Array(Buffer.from("hello"));
    const token1 = await Token.create(root, k2, msg1);

    const k3 = KeyPair.new();
    const msg2 = new Uint8Array(Buffer.from("world"));
    const token2 = await token1.append(k3, msg2);

    // verify chain
    await token2.verify(root.public());
    console.log("✅ token verified");

    // Seal example
    // Build final seal over concat(data || next_key) for each block (matches verify())
    let buf = new Uint8Array(0);
    for (const b of token2.blocks) {
      buf = concat(buf, b.data, b.next_key.toBytes());
    }
    const sealSig = await ed.sign(buf, k3.private().toBytes());
    const sealed = new Token(
      token2.root,
      token2.blocks,
      new TokenNext.Seal(sealSig)
    );
    await sealed.verify(root.public());
    console.log("✅ sealed token verified");
  })().catch((e) => {
    console.error("❌ error:", e);
    process.exit(1);
  });
}
