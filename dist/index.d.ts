/// <reference types="node" />
declare type Hex = string;
declare type Path = string;
declare type Keys = {
    key: Buffer;
    chainCode: Buffer;
};
export declare const getMasterKeyFromSeed: (seed: Hex) => Keys;
export declare const getPublicKey: (privateKey: Buffer, withZeroByte?: boolean) => Buffer;
export declare const isValidPath: (path: string) => boolean;
export declare const derivePath: (path: Path, seed: Hex, offset?: number) => Keys;
export default class HDKey {
    readonly version: number;
    depth: number;
    index: number;
    chainCode: Buffer;
    parentFingerprint: number;
    private _privateKey;
    private _publicKey;
    private _identifier;
    private _fingerprint;
    constructor(version?: number);
    get privateKey(): Buffer;
    get publicKey(): Buffer;
    private set prvKey(value);
    get privateExtendedKey(): any;
    static fromMasterSeed(seed: Hex, version?: number): HDKey;
    static fromExtendedKey(base58key: Hex, version?: number): HDKey;
    derive(path: string): HDKey;
    deriveChild(index: number): HDKey;
}
export {};
