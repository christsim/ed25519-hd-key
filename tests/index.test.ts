import 'mocha';
import { expect } from 'chai';
import HDKey, {derivePath, getPublicKey, isValidPath} from '../dist';

describe('ED25519 HD Key', function (){
    it('can get public keys', function () {
        expect(getPublicKey(Buffer.from('68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3', 'hex')).toString('hex'))
            .to.equal('8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c');
        expect(getPublicKey(Buffer.from('30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662', 'hex')).toString('hex'))
            .to.equal('8abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c');
        expect(getPublicKey(Buffer.from('8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793', 'hex')).toString('hex'))
            .to.equal('3c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a');
    });

    it('can get public keys with zeroBytes - (33 bytes)', function () {
        expect(getPublicKey(Buffer.from('68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3', 'hex'), true).toString('hex'))
            .to.equal('008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c');
        expect(getPublicKey(Buffer.from('30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662', 'hex'), true).toString('hex'))
            .to.equal('008abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c');
        expect(getPublicKey(Buffer.from('8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793', 'hex'), true).toString('hex'))
            .to.equal('003c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a');
    });

    it('test valid paths', function () {
        expect(isValidPath('m/0/1/2/3/4')).to.be.false;
        expect(isValidPath('m/0')).to.be.false;
        expect(isValidPath(`m/0'`)).to.be.true;
        expect(isValidPath(`m/0'/123'`)).to.be.true;
        expect(isValidPath(`m/0'/1'/3'/4/5`)).to.be.false;
        expect(isValidPath(`m/0/1/2/3/4'/5'`)).to.be.false;
        expect(isValidPath(`m/0'/123'/1/2/4'`)).to.be.false;
        expect(isValidPath('m/12/ab/cd')).to.be.false;
        expect(isValidPath('m/a/b/c/d')).to.be.false;
        expect(isValidPath('m/a/b/12/34/5')).to.be.false;
        expect(isValidPath(`m/a'/b'/c'`)).to.be.false;
    });

    it('derive paths', function () {
        {
            const derivedKey = derivePath(`m/0'/1'/2'/2'`, '000102030405060708090a0b0c0d0e0f');
            expect(derivedKey.key.toString('hex')).to.be
                .equal('30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662');
            expect(derivedKey.chainCode.toString('hex')).to.be
                .equal('8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc');
        }

        {
            const derivedKey = derivePath(`m/0'/1'`, '000102030405060708090a0b0c0d0e0f');
            expect(derivedKey.key.toString('hex')).to.be
                .equal('b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2');
            expect(derivedKey.chainCode.toString('hex')).to.be
                .equal('a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14');
        }
    });

    it('Derive HD Wallet public and private keys from seed', function () {
        const hdkey = HDKey.fromMasterSeed('000102030405060708090a0b0c0d0e0f');

        expect(hdkey.derive(`m/0'`).privateKey.toString('hex')).to
            .equal('68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3');
        expect(hdkey.derive(`m/0'`).publicKey.toString('hex')).to
            .equal('8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c');
        expect(hdkey.derive(`m/0'`).publicKeyWithZeroByte.toString('hex')).to
            .equal('008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c');

        expect(hdkey.derive(`m/0'/1'`).privateKey.toString('hex')).to
            .equal('b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2');
        expect(hdkey.derive(`m/0'/1'`).publicKey.toString('hex')).to
            .equal('1932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187');
        expect(hdkey.derive(`m/0'/1'`).publicKeyWithZeroByte.toString('hex')).to
            .equal('001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187');

        expect(hdkey.derive(`m/0'/1'/2'/2'`).privateKey.toString('hex')).to
            .equal('30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662');
        expect(hdkey.derive(`m/0'/1'/2'/2'`).publicKey.toString('hex')).to
            .equal('8abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c');
        expect(hdkey.derive(`m/0'/1'/2'/2'`).publicKeyWithZeroByte.toString('hex')).to
            .equal('008abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c');

        expect(hdkey.derive(`m/0'/1'/2'/2'/1000000000'`).privateKey.toString('hex')).to
            .equal('8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793');
        expect(hdkey.derive(`m/0'/1'/2'/2'/1000000000'`).publicKey.toString('hex')).to
            .equal('3c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a');
        expect(hdkey.derive(`m/0'/1'/2'/2'/1000000000'`).publicKeyWithZeroByte.toString('hex')).to
            .equal('003c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a');
    });

    it('Derive HD wallet public and private keys from xpriv', function () {
        // seed: 000102030405060708090a0b0c0d0e0f & path: m/0'/1'
        const xpriv = 'xprv9wASP9Ev8ArFsnymBSZfDnqpdeBhSoQCN7jVJTxMihfWDCnbQ9MZpGr7N5Q9gY3P66ZtdwNXrQQHHTwWNhHA4PyTxfGDsGMwzUj9XtMLmTF';
        const hdkey = HDKey.fromExtendedKey(xpriv);

        expect(hdkey.derive(`m/2'/2'`).privateKey.toString('hex')).to
            .equal('30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662');
        expect(hdkey.derive(`m/2'/2'`).publicKey.toString('hex')).to
            .equal('8abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c');
        expect(hdkey.derive(`m/2'/2'`).publicKeyWithZeroByte.toString('hex')).to
            .equal('008abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c');

        expect(hdkey.derive(`m/2'/2'/1000000000'`).privateKey.toString('hex')).to
            .equal('8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793');
        expect(hdkey.derive(`m/2'/2'/1000000000'`).publicKey.toString('hex')).to
            .equal('3c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a');
        expect(hdkey.derive(`m/2'/2'/1000000000'`).publicKeyWithZeroByte.toString('hex')).to
            .equal('003c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a');
    });
})