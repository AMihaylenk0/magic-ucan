import * as ed from "@noble/ed25519";
import * as ucan from "ucans";
import * as uint8arrays from "uint8arrays";
import crypto from "crypto";

// Shimmed Magic Api
// --------------------------

// Magic bytes to prefix an edwards key with
// Multicodec for ed25519, varint encoded
// https://github.com/multiformats/multicodec/blob/e9ecf587558964715054a0afcc01f7ace220952c/table.csv#L94
export const EDWARDS_DID_PREFIX = new Uint8Array([0xed, 0x01]);

export class Magic {
  privateKey: Uint8Array;

  constructor() {
    this.privateKey = ed.utils.randomPrivateKey();
  }

  async signUcan(bytes: Uint8Array): Promise<Uint8Array> {
    return ed.sign(bytes, this.privateKey);
  }

  async signAicTx(bytes: Uint8Array): Promise<Uint8Array> {
    return ed.sign(bytes, this.privateKey);
  }

  async getPublicKey() {
    const pubkey = await ed.getPublicKey(this.privateKey);
    const prefixed = uint8arrays.concat([EDWARDS_DID_PREFIX, pubkey]);
    const base58 = uint8arrays.toString(prefixed, "base58btc");
    return `did:key:z${base58}`;
  }
}

// Example Implementation
// ---------------------------

const run = async () => {
  const magic = new Magic();
  const magicDid = await magic.getPublicKey();
  const { type } = await ucan.didToPublicKey(magicDid);
  if (magicDid.length !== 56) {
    throw new Error("Expected did:key to be 56 chars long");
  }
  if (type !== "ed25519") {
    throw new Error("Expected an Ed25519 prefixed did:key");
  }

  for (let i = 0; i < 100; i++) {
    const bytes = await randomBytes();
    const ucanSig = await magic.signUcan(bytes);
    const aicSig = await magic.signAicTx(bytes);
    if (!uint8arrays.equals(ucanSig, aicSig)) {
      throw new Error("Expected equal signatures from same key");
    }
    const validSig = await ucan.verifySignature(bytes, ucanSig, magicDid);
    if (!validSig) {
      throw new Error("Not a valid sig");
    }
  }
  console.log("Everything looks good 🎉");
};

run();

const randomBytes = async (): Promise<Uint8Array> => {
  const len = Math.floor(Math.random() * 10000);
  return crypto.randomBytes(len);
};
