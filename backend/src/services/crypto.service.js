/**
 * Cryptography Service
 * Handles RSA keypair generation, AES encryption, and digital signatures
 */
const crypto = require('crypto');

class CryptoService {
    /**
     * Generate RSA keypair for a user
     * @returns {Object} { publicKey, privateKey } in PEM format
     */
    static generateKeyPair() {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });
        return { publicKey, privateKey };
    }

    /**
     * Derive encryption key from password using PBKDF2
     */
    static deriveKeyFromPassword(password, salt) {
        return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
    }

    /**
     * Encrypt private key with password-derived key (AES-256-GCM)
     */
    static encryptPrivateKey(privateKey, password) {
        const salt = crypto.randomBytes(16);
        const key = this.deriveKeyFromPassword(password, salt);
        const iv = crypto.randomBytes(12);

        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        let encrypted = cipher.update(privateKey, 'utf8', 'base64');
        encrypted += cipher.final('base64');
        const authTag = cipher.getAuthTag();

        return {
            encryptedPrivateKey: encrypted,
            salt: salt.toString('base64'),
            iv: iv.toString('base64'),
            tag: authTag.toString('base64')
        };
    }

    /**
     * Decrypt private key with password-derived key
     */
    static decryptPrivateKey(encryptedData, password) {
        const salt = Buffer.from(encryptedData.salt, 'base64');
        const iv = Buffer.from(encryptedData.iv, 'base64');
        const tag = Buffer.from(encryptedData.tag, 'base64');
        const key = this.deriveKeyFromPassword(password, salt);

        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(tag);

        let decrypted = decipher.update(encryptedData.encryptedPrivateKey, 'base64', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    }

    /**
     * Generate AES-256 key for content encryption
     */
    static generateAESKey() {
        return crypto.randomBytes(32);
    }

    /**
     * Encrypt content with AES-256-GCM
     */
    static encryptContent(plaintext, aesKey) {
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);

        let encrypted = cipher.update(plaintext, 'utf8', 'base64');
        encrypted += cipher.final('base64');
        const authTag = cipher.getAuthTag();

        return {
            encryptedBlob: encrypted,
            iv: iv.toString('base64'),
            authTag: authTag.toString('base64')
        };
    }

    /**
     * Decrypt content with AES-256-GCM
     */
    static decryptContent(encryptedBlob, iv, authTag, aesKey) {
        const decipher = crypto.createDecipheriv(
            'aes-256-gcm',
            aesKey,
            Buffer.from(iv, 'base64')
        );
        decipher.setAuthTag(Buffer.from(authTag, 'base64'));

        let decrypted = decipher.update(encryptedBlob, 'base64', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    }

    /**
     * Wrap AES key with recipient's public RSA key (RSA-OAEP)
     */
    static wrapAESKey(aesKey, publicKeyPem) {
        const wrapped = crypto.publicEncrypt(
            {
                key: publicKeyPem,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            },
            aesKey
        );
        return wrapped.toString('base64');
    }

    /**
     * Unwrap AES key with user's private RSA key
     */
    static unwrapAESKey(wrappedKey, privateKeyPem) {
        const unwrapped = crypto.privateDecrypt(
            {
                key: privateKeyPem,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            },
            Buffer.from(wrappedKey, 'base64')
        );
        return unwrapped;
    }

    /**
     * Sign content with RSA-PSS + SHA-256
     */
    static signContent(content, privateKeyPem) {
        const sign = crypto.createSign('RSA-SHA256');
        sign.update(content);
        sign.end();
        return sign.sign(
            {
                key: privateKeyPem,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
            },
            'base64'
        );
    }

    /**
     * Verify signature with RSA-PSS + SHA-256
     */
    static verifySignature(content, signature, publicKeyPem) {
        const verify = crypto.createVerify('RSA-SHA256');
        verify.update(content);
        verify.end();
        return verify.verify(
            {
                key: publicKeyPem,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST
            },
            signature,
            'base64'
        );
    }

    /**
     * Hash content with SHA-256
     */
    static hashContent(content) {
        return crypto.createHash('sha256').update(content).digest('hex');
    }

    /**
     * Generate a random verification code
     */
    static generateVerificationCode() {
        return crypto.randomBytes(16).toString('hex');
    }
}

module.exports = CryptoService;
