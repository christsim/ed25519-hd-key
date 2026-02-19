import createHmac from 'create-hmac';
import * as nacl from 'tweetnacl';
import * as bs58check from 'bs58check';
import * as crypto from 'crypto';
import { replaceDerive, pathRegex } from './utils';

const assert = require('assert');

interface Nacl {
    crypto_sign_seed_keypair: (
        val: Buffer,
    ) => { signPk: Buffer; signSk: Buffer };
}
type Hex = string;
type Path = string;

type Keys = {
    key: Buffer;
    chainCode: Buffer;
};

const ED25519_CURVE = 'ed25519 seed';
const HARDENED_OFFSET = 0x80000000;

export const getMasterKeyFromSeed = (seed: Hex): Keys => {
    const hmac = createHmac('sha512', ED25519_CURVE);
    const I = hmac.update(Buffer.from(seed, 'hex')).digest();
    const IL = I.slice(0, 32);
    const IR = I.slice(32);
    return {
        key: IL,
        chainCode: IR,
    };
};

const CKDPriv = ({ key, chainCode }: Keys, index: number): Keys => {
    const indexBuffer = Buffer.allocUnsafe(4);
    indexBuffer.writeUInt32BE(index, 0);

    const data = Buffer.concat([Buffer.alloc(1, 0), key, indexBuffer]);

    const I = createHmac('sha512', chainCode)
        .update(data)
        .digest();
    const IL = I.slice(0, 32);
    const IR = I.slice(32);
    return {
        key: IL,
        chainCode: IR,
    };
};

export const getPublicKey = (privateKey: Buffer, withZeroByte = false): Buffer => {
    const keyPair = nacl.sign.keyPair.fromSeed(privateKey);
    const signPk = keyPair.secretKey.subarray(32);
    const zero = Buffer.alloc(1, 0);
    return withZeroByte ?
        Buffer.concat([zero, Buffer.from(signPk)]) :
        Buffer.from(signPk);
};

export const isValidPath = (path: string): boolean => {
    if (!pathRegex.test(path)) {
        return false;
    }
    return !path
        .split('/')
        .slice(1)
        .map(replaceDerive)
        .some(isNaN as any /* ts T_T*/);
};

export const derivePath = (path: Path, seed: Hex, offset = HARDENED_OFFSET): Keys => {
    if (!isValidPath(path)) {
        throw new Error('Invalid derivation path');
    }

    const { key, chainCode } = getMasterKeyFromSeed(seed);
    const segments = path
        .split('/')
        .slice(1)
        .map(replaceDerive)
        .map(el => parseInt(el, 10));

    return segments.reduce(
        (parentKeys, segment) => CKDPriv(parentKeys, segment + offset),
        { key, chainCode },
    );
};


const BIP32_PRIVATE_VERSION = 0x0488ADE4;
const LEN = 78;

function serialize(hdkey: HDKey, version: number, key: Buffer): Buffer {
    const buffer = Buffer.allocUnsafe(LEN);

    buffer.writeUInt32BE(version, 0)
    buffer.writeUInt8(hdkey.depth, 4)

    const fingerprint = hdkey.depth ? hdkey.parentFingerprint : 0x00000000
    buffer.writeUInt32BE(fingerprint, 5)
    buffer.writeUInt32BE(hdkey.index, 9)

    hdkey.chainCode.copy(buffer, 13)
    key.copy(buffer, 45)

    return buffer
}

function hash160 (buf: Buffer): Buffer {
    const sha = crypto.createHash('sha256').update(buf).digest();
    return crypto.createHash('ripemd160').update(sha).digest();
}

export default class HDKey {
    readonly version: number;
    depth: number = 0;
    index: number = 0;
    chainCode: Buffer = null;
    parentFingerprint: number = 0;
    private _privateKey: Buffer = null;
    private _publicKey: Buffer = null;
    private _identifier: Buffer = null;
    private _fingerprint: number = 0;

    constructor(version?: number) {
        this.version = version || BIP32_PRIVATE_VERSION;
    }

    public get privateKey(): Buffer {
        return this._privateKey;
    }

    public get publicKey(): Buffer {
        return this._publicKey;
    }

    public get publicKeyWithZeroByte(): Buffer {
        return getPublicKey(this._privateKey, true);
    }

    private set prvKey(value: Buffer) {
        assert.equal(value.length, 32, 'Private key must be 32 bytes.');
        this._privateKey = value;
        this._publicKey = getPublicKey(this._privateKey);
        this._identifier = hash160(this._publicKey);
        this._fingerprint = this._identifier.slice(0, 4).readUInt32BE(0);
    }

    public get privateExtendedKey() {
        if (this._privateKey) {
            return bs58check.encode(
                serialize(
                    this,
                    this.version,
                    Buffer.concat([Buffer.alloc(1, 0), this.privateKey])
                )
            );
        }
        return null;
    }

    static fromMasterSeed(seed: Hex, version: number = BIP32_PRIVATE_VERSION): HDKey {
        const { key, chainCode } = getMasterKeyFromSeed(seed);
        const hdkey = new HDKey(version);
        hdkey.prvKey = key;
        hdkey.chainCode = chainCode;
        return hdkey;
    }

    static fromExtendedKey(base58key: Hex, version: number = BIP32_PRIVATE_VERSION): HDKey {
        const hdkey = new HDKey(version);
        const keyBuffer = bs58check.decode(base58key);
        const keyVersion = keyBuffer.readUInt32BE(0);
        assert(keyVersion === BIP32_PRIVATE_VERSION, 'version mismatch: does not match private');

        hdkey.depth = keyBuffer.readUInt8(4);
        hdkey.parentFingerprint = keyBuffer.readUInt32BE(5);
        hdkey.index = keyBuffer.readUInt32BE(9);
        hdkey.chainCode = keyBuffer.slice(13, 45);

        const key = keyBuffer.slice(45);
        hdkey.prvKey = key.slice(1);

        return hdkey;
    }

    derive(path: string): HDKey {
        if (path.toLowerCase() === 'm' || path.toLowerCase() === 'm\'') {
            return this;
        }

        const entries = path.split('/');
        let hdkey = this as HDKey;
        entries.forEach(function (c, i) {
            if (i === 0) {
                assert(/^[mM]/.test(c), 'Path must start with "m" or "M"')
                return;
            }

            const childIndex = parseInt(c, 10);
            hdkey = hdkey.deriveChild(childIndex);
        });

        return hdkey;
    }

    deriveChild(index: number): HDKey {
        const hardenedIndex = (index >= HARDENED_OFFSET) ? index : (index + HARDENED_OFFSET);

        assert(this.privateKey, 'Could not derive hardened child key');
        const { key, chainCode } = CKDPriv({ key: this._privateKey, chainCode: this.chainCode }, hardenedIndex);

        const hd = new HDKey(this.version);
        hd.prvKey = key;
        hd.chainCode = chainCode;
        hd.depth = this.depth + 1;
        hd.parentFingerprint = this._fingerprint;
        hd.index = hardenedIndex;

        return hd;
    }
}