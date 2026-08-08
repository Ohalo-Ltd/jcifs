/*
 * © 2025 CodeLibs, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package org.codelibs.jcifs.smb.internal.smb2;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.DialectVersion;
import org.codelibs.jcifs.smb.internal.smb2.nego.EncryptionNegotiateContext;
import org.codelibs.jcifs.smb.util.Crypto;

/**
 * SMB2/SMB3 Encryption Context
 *
 * Manages encryption and decryption operations for SMB2/SMB3 sessions.
 * Handles both AES-CCM (SMB 3.0/3.0.2) and AES-GCM (SMB 3.1.1) cipher suites.
 *
 * @author mbechler
 */
public class Smb2EncryptionContext {

    private final int cipherId;
    private final DialectVersion dialect;
    private final byte[] encryptionKey;
    private final byte[] decryptionKey;
    private final AtomicLong nonceCounter = new AtomicLong(0);
    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * AES-128-CCM cipher identifier for SMB3 encryption
     */
    public static final int CIPHER_AES_128_CCM = EncryptionNegotiateContext.CIPHER_AES128_CCM;
    /**
     * AES-128-GCM cipher identifier for SMB3.1.1 encryption
     */
    public static final int CIPHER_AES_128_GCM = EncryptionNegotiateContext.CIPHER_AES128_GCM;
    // Note: AES-256 variants are not currently defined in the negotiate context

    /**
     * Transform header flag indicating the message is encrypted
     */
    public static final int TRANSFORM_FLAG_ENCRYPTED = 0x0001;

    /**
     * Create encryption context
     *
     * @param cipherId
     *            negotiated cipher identifier
     * @param dialect
     *            SMB dialect version
     * @param encryptionKey
     *            key for client->server encryption
     * @param decryptionKey
     *            key for server->client decryption
     */
    public Smb2EncryptionContext(final int cipherId, final DialectVersion dialect, final byte[] encryptionKey, final byte[] decryptionKey) {
        this.cipherId = cipherId;
        this.dialect = dialect;
        this.encryptionKey = encryptionKey.clone();
        this.decryptionKey = decryptionKey.clone();
    }

    /**
     * Get the negotiated cipher identifier
     * @return the negotiated cipher ID
     */
    public int getCipherId() {
        return this.cipherId;
    }

    /**
     * Get the SMB dialect version
     * @return the SMB dialect version
     */
    public DialectVersion getDialect() {
        return this.dialect;
    }

    /**
     * Get the nonce length used by the negotiated cipher.
     *
     * Per MS-SMB2 2.2.41 the transform header carries a 16-byte nonce field,
     * but only the cipher's nonce length is significant: 11 bytes for AES-CCM
     * and 12 bytes for AES-GCM. The remainder of the field must be zero.
     *
     * @return the cipher nonce length in bytes
     */
    public int getNonceLength() {
        return isGCMCipher() ? 12 : 11;
    }

    /**
     * Generate a unique nonce for encryption
     *
     * @return nonce of the cipher's nonce length (see {@link #getNonceLength()})
     */
    public byte[] generateNonce() {
        final byte[] nonce = new byte[getNonceLength()];

        // Use combination of counter and random data for uniqueness; the counter
        // alone already guarantees no reuse within this context's lifetime
        final long counter = this.nonceCounter.incrementAndGet();
        System.arraycopy(longToBytes(counter), 0, nonce, 0, 8);

        // Fill the remaining bytes with random data
        final byte[] randomBytes = new byte[nonce.length - 8];
        this.secureRandom.nextBytes(randomBytes);
        System.arraycopy(randomBytes, 0, nonce, 8, randomBytes.length);

        return nonce;
    }

    /**
     * Encrypt an SMB2 message
     *
     * @param message
     *            plaintext message to encrypt
     * @param sessionId
     *            session identifier
     * @return encrypted message with transform header
     * @throws CIFSException
     *             if encryption fails
     */
    public byte[] encryptMessage(final byte[] message, final long sessionId) throws CIFSException {
        try {
            final byte[] nonce = generateNonce();
            final int flags = getTransformFlags();

            // the transform header nonce field is 16 bytes, zero-padded beyond the
            // cipher's nonce length (MS-SMB2 2.2.41)
            final Smb2TransformHeader transformHeader = new Smb2TransformHeader(Arrays.copyOf(nonce, 16), message.length, flags, sessionId);
            final byte[] associatedData = transformHeader.getAssociatedData();

            final Cipher cipher = createCipher(true, nonce);
            cipher.updateAAD(associatedData);
            final byte[] encrypted = cipher.doFinal(message);

            // Split ciphertext and authentication tag: the tag is carried in the
            // transform header signature field, not appended to the payload
            final int tagLength = getAuthTagLength();
            final byte[] ciphertext = new byte[encrypted.length - tagLength];
            final byte[] authTag = new byte[tagLength];
            System.arraycopy(encrypted, 0, ciphertext, 0, ciphertext.length);
            System.arraycopy(encrypted, ciphertext.length, authTag, 0, tagLength);

            // Set authentication tag in transform header
            transformHeader.setSignature(authTag);

            // Build final encrypted message
            final byte[] result = new byte[Smb2TransformHeader.TRANSFORM_HEADER_SIZE + ciphertext.length];
            transformHeader.encode(result, 0);
            System.arraycopy(ciphertext, 0, result, Smb2TransformHeader.TRANSFORM_HEADER_SIZE, ciphertext.length);

            return result;
        } catch (final Exception e) {
            throw new CIFSException("Failed to encrypt message", e);
        }
    }

    /**
     * Decrypt an SMB2 message
     *
     * @param encryptedMessage
     *            encrypted message with transform header
     * @return decrypted plaintext message
     * @throws CIFSException
     *             if decryption fails
     */
    public byte[] decryptMessage(final byte[] encryptedMessage) throws CIFSException {
        // Parse transform header
        final Smb2TransformHeader transformHeader = Smb2TransformHeader.decode(encryptedMessage, 0);
        checkTransformFlags(transformHeader.getFlags());
        try {
            final byte[] associatedData = transformHeader.getAssociatedData();
            // only the cipher's nonce length is used, the rest of the 16-byte
            // field is padding to be ignored on receipt (MS-SMB2 2.2.41)
            final byte[] nonce = Arrays.copyOf(transformHeader.getNonce(), getNonceLength());
            final byte[] authTag = transformHeader.getSignature();

            // Extract ciphertext
            final int ciphertextLength = encryptedMessage.length - Smb2TransformHeader.TRANSFORM_HEADER_SIZE;
            final byte[] ciphertext = new byte[ciphertextLength];
            System.arraycopy(encryptedMessage, Smb2TransformHeader.TRANSFORM_HEADER_SIZE, ciphertext, 0, ciphertextLength);

            final Cipher cipher = createCipher(false, nonce);
            cipher.updateAAD(associatedData);

            // Combine ciphertext and auth tag for decryption
            final byte[] input = new byte[ciphertext.length + authTag.length];
            System.arraycopy(ciphertext, 0, input, 0, ciphertext.length);
            System.arraycopy(authTag, 0, input, ciphertext.length, authTag.length);

            return cipher.doFinal(input);
        } catch (final Exception e) {
            throw new CIFSException("Failed to decrypt message", e);
        }
    }

    /**
     * Validate the Flags/EncryptionAlgorithm field of a received transform
     * header against the negotiated cipher, per MS-SMB2 3.2.5.1.1.1: for
     * SMB 3.1.1 the field must be exactly 0x0001 (Encrypted), for SMB 3.0.x it
     * must equal the negotiated encryption algorithm.
     *
     * @param flags received Flags/EncryptionAlgorithm value
     * @throws CIFSException if the message must be discarded
     */
    private void checkTransformFlags(final int flags) throws CIFSException {
        if (this.dialect.atLeast(DialectVersion.SMB311)) {
            if (flags != TRANSFORM_FLAG_ENCRYPTED) {
                throw new CIFSException("Invalid transform header flags 0x" + Integer.toHexString(flags));
            }
        } else if (flags != this.cipherId) {
            throw new CIFSException(
                    "Transform header encryption algorithm 0x" + Integer.toHexString(flags) + " does not match the negotiated cipher");
        }
    }

    private boolean isGCMCipher() {
        return this.cipherId == CIPHER_AES_128_GCM;
    }

    private int getKeyLength() {
        // Currently only AES-128 is supported
        if (this.cipherId == CIPHER_AES_128_CCM || this.cipherId == CIPHER_AES_128_GCM) {
            return 16;
        }
        throw new IllegalArgumentException("Unsupported cipher: " + this.cipherId);
    }

    private int getAuthTagLength() {
        return 16; // All SMB3 ciphers use 16-byte authentication tags
    }

    private int getTransformFlags() {
        if (this.dialect.atLeast(DialectVersion.SMB311)) {
            return TRANSFORM_FLAG_ENCRYPTED;
        }
        // For SMB 3.0/3.0.2, this field contains the encryption algorithm
        return this.cipherId;
    }

    /**
     * Create an initialized AEAD cipher for the negotiated algorithm.
     *
     * Both ciphers are obtained through JCE from the provider configured via
     * {@link Crypto#getProvider()}, so an installed custom provider (e.g. a
     * FIPS-validated one) is honoured for the AEAD operations as well.
     * GCMParameterSpec doubles as the parameter spec for CCM, carrying the
     * nonce and tag length.
     *
     * @param encrypt whether to initialize for encryption (true) or decryption
     * @param nonce nonce of the cipher's nonce length
     * @return initialized cipher
     */
    private Cipher createCipher(final boolean encrypt, final byte[] nonce) throws GeneralSecurityException {
        final String transformation = isGCMCipher() ? "AES/GCM/NoPadding" : "AES/CCM/NoPadding";
        final Cipher cipher = Cipher.getInstance(transformation, Crypto.getProvider());
        final SecretKeySpec keySpec = new SecretKeySpec(encrypt ? this.encryptionKey : this.decryptionKey, "AES");
        final GCMParameterSpec spec = new GCMParameterSpec(getAuthTagLength() * 8, nonce);
        cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, keySpec, spec);
        return cipher;
    }

    private static byte[] longToBytes(final long value) {
        final byte[] bytes = new byte[8];
        for (int i = 0; i < 8; i++) {
            bytes[i] = (byte) (value >>> 8 * (7 - i));
        }
        return bytes;
    }
}
