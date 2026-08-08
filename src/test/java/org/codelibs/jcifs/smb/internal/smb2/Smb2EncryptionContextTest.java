package org.codelibs.jcifs.smb.internal.smb2;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;

import org.codelibs.jcifs.smb.DialectVersion;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Test class for Smb2EncryptionContext.
 * Tests the available public API methods of the encryption context.
 */
@DisplayName("Smb2EncryptionContext Tests")
class Smb2EncryptionContextTest {

    private byte[] testEncryptionKey;
    private byte[] testDecryptionKey;
    private Smb2EncryptionContext encryptionContext;

    @BeforeEach
    void setUp() {
        // Initialize test keys
        testEncryptionKey = new byte[16]; // 128-bit key
        testDecryptionKey = new byte[16]; // 128-bit key
        new SecureRandom().nextBytes(testEncryptionKey);
        new SecureRandom().nextBytes(testDecryptionKey);

        // Create encryption context with required parameters
        encryptionContext = new Smb2EncryptionContext(1, DialectVersion.SMB311, testEncryptionKey, testDecryptionKey);
    }

    @Test
    @DisplayName("Should create encryption context with valid parameters")
    void testConstructor() {
        // When
        Smb2EncryptionContext context = new Smb2EncryptionContext(1, DialectVersion.SMB311, testEncryptionKey, testDecryptionKey);

        // Then
        assertNotNull(context, "Encryption context should be created");
        assertEquals(1, context.getCipherId(), "Cipher ID should match");
        assertEquals(DialectVersion.SMB311, context.getDialect(), "Dialect should match");
    }

    @Test
    @DisplayName("Should return correct cipher ID")
    void testGetCipherId() {
        // When
        int cipherId = encryptionContext.getCipherId();

        // Then
        assertEquals(1, cipherId, "Should return the cipher ID set in constructor");
    }

    @Test
    @DisplayName("Should return correct dialect version")
    void testGetDialect() {
        // When
        DialectVersion dialect = encryptionContext.getDialect();

        // Then
        assertEquals(DialectVersion.SMB311, dialect, "Should return the dialect set in constructor");
    }

    @Test
    @DisplayName("Should handle SMB 3.0 dialect")
    void testSMB300Dialect() {
        // When
        Smb2EncryptionContext context = new Smb2EncryptionContext(1, DialectVersion.SMB300, testEncryptionKey, testDecryptionKey);

        // Then
        assertEquals(DialectVersion.SMB300, context.getDialect(), "Should support SMB 3.0 dialect");
    }

    @Test
    @DisplayName("Should handle SMB 3.0.2 dialect")
    void testSMB302Dialect() {
        // When
        Smb2EncryptionContext context = new Smb2EncryptionContext(1, DialectVersion.SMB302, testEncryptionKey, testDecryptionKey);

        // Then
        assertEquals(DialectVersion.SMB302, context.getDialect(), "Should support SMB 3.0.2 dialect");
    }

    @Test
    @DisplayName("Should handle different cipher IDs")
    void testDifferentCipherIds() {
        // Test cipher ID 1 (AES-CCM)
        Smb2EncryptionContext context1 = new Smb2EncryptionContext(1, DialectVersion.SMB311, testEncryptionKey, testDecryptionKey);
        assertEquals(1, context1.getCipherId(), "Should handle cipher ID 1");

        // Test cipher ID 2 (AES-GCM)
        Smb2EncryptionContext context2 = new Smb2EncryptionContext(2, DialectVersion.SMB311, testEncryptionKey, testDecryptionKey);
        assertEquals(2, context2.getCipherId(), "Should handle cipher ID 2");
    }

    @Test
    @DisplayName("Should throw exception for null encryption key")
    void testNullEncryptionKey() {
        // When/Then
        assertThrows(NullPointerException.class, () -> {
            new Smb2EncryptionContext(1, DialectVersion.SMB311, null, testDecryptionKey);
        }, "Should throw NullPointerException for null encryption key");
    }

    @Test
    @DisplayName("Should throw exception for null decryption key")
    void testNullDecryptionKey() {
        // When/Then
        assertThrows(NullPointerException.class, () -> {
            new Smb2EncryptionContext(1, DialectVersion.SMB311, testEncryptionKey, null);
        }, "Should throw NullPointerException for null decryption key");
    }

    @Test
    @DisplayName("Should accept null dialect during construction")
    void testNullDialect() {
        // When/Then
        assertDoesNotThrow(() -> {
            Smb2EncryptionContext context = new Smb2EncryptionContext(1, null, testEncryptionKey, testDecryptionKey);
            assertNull(context.getDialect(), "Dialect should be null");
        }, "Should accept null dialect during construction");
    }

    @Test
    @DisplayName("Should accept empty keys")
    void testEmptyKeys() {
        // Given
        byte[] emptyKey = new byte[0];

        // When/Then
        assertDoesNotThrow(() -> {
            Smb2EncryptionContext context = new Smb2EncryptionContext(1, DialectVersion.SMB311, emptyKey, emptyKey);
            assertNotNull(context, "Context should be created with empty keys");
        }, "Should accept empty keys");
    }

    @Test
    @DisplayName("Should accept different key sizes")
    void testDifferentKeySizes() {
        // Given
        byte[] key128 = new byte[16]; // 128-bit
        byte[] key256 = new byte[32]; // 256-bit
        new SecureRandom().nextBytes(key128);
        new SecureRandom().nextBytes(key256);

        // When/Then
        assertDoesNotThrow(() -> {
            Smb2EncryptionContext context = new Smb2EncryptionContext(1, DialectVersion.SMB311, key128, key256);
            assertNotNull(context, "Context should be created with different key sizes");
        }, "Should accept different key sizes");
    }

    @Test
    @DisplayName("Should be immutable after creation")
    void testImmutability() {
        // Given
        int originalCipherId = encryptionContext.getCipherId();
        DialectVersion originalDialect = encryptionContext.getDialect();

        // When - Modify the original key array
        testEncryptionKey[0] = (byte) ~testEncryptionKey[0];

        // Then - Context should not be affected by external modifications
        assertEquals(originalCipherId, encryptionContext.getCipherId(), "Cipher ID should remain unchanged");
        assertEquals(originalDialect, encryptionContext.getDialect(), "Dialect should remain unchanged");
    }

    @Test
    @DisplayName("Should generate unique nonces of the cipher nonce length")
    void testGenerateNonce() {
        // When - setUp uses cipher 1 (AES-128-CCM)
        byte[] nonce1 = encryptionContext.generateNonce();
        byte[] nonce2 = encryptionContext.generateNonce();

        // Then
        assertNotNull(nonce1, "First nonce should not be null");
        assertNotNull(nonce2, "Second nonce should not be null");
        assertEquals(11, nonce1.length, "AES-CCM nonce should be 11 bytes");
        assertEquals(11, nonce2.length, "AES-CCM nonce should be 11 bytes");
        assertFalse(java.util.Arrays.equals(nonce1, nonce2), "Consecutive nonces should be different");
    }

    @Test
    @DisplayName("Should use the MS-SMB2 nonce lengths: 11 bytes for CCM, 12 bytes for GCM")
    void testNonceLengths() {
        Smb2EncryptionContext ccm = new Smb2EncryptionContext(Smb2EncryptionContext.CIPHER_AES_128_CCM, DialectVersion.SMB300,
                testEncryptionKey, testDecryptionKey);
        Smb2EncryptionContext gcm = new Smb2EncryptionContext(Smb2EncryptionContext.CIPHER_AES_128_GCM, DialectVersion.SMB311,
                testEncryptionKey, testDecryptionKey);

        assertEquals(11, ccm.getNonceLength(), "AES-CCM uses an 11-byte nonce");
        assertEquals(12, gcm.getNonceLength(), "AES-GCM uses a 12-byte nonce");
        assertEquals(11, ccm.generateNonce().length, "Generated CCM nonce should have the cipher nonce length");
        assertEquals(12, gcm.generateNonce().length, "Generated GCM nonce should have the cipher nonce length");
    }

    @Test
    @DisplayName("Should zero-pad the 16-byte transform header nonce field beyond the cipher nonce length")
    void testTransformHeaderNoncePadding() throws Exception {
        byte[] message = "nonce padding test".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        Smb2EncryptionContext ccm = new Smb2EncryptionContext(Smb2EncryptionContext.CIPHER_AES_128_CCM, DialectVersion.SMB300,
                testEncryptionKey, testDecryptionKey);
        Smb2TransformHeader ccmHeader = Smb2TransformHeader.decode(ccm.encryptMessage(message, 0x1234L), 0);
        for (int i = 11; i < 16; i++) {
            assertEquals(0, ccmHeader.getNonce()[i], "CCM nonce field must be zero-padded from byte 11");
        }

        Smb2EncryptionContext gcm = new Smb2EncryptionContext(Smb2EncryptionContext.CIPHER_AES_128_GCM, DialectVersion.SMB311,
                testEncryptionKey, testDecryptionKey);
        Smb2TransformHeader gcmHeader = Smb2TransformHeader.decode(gcm.encryptMessage(message, 0x1234L), 0);
        for (int i = 12; i < 16; i++) {
            assertEquals(0, gcmHeader.getNonce()[i], "GCM nonce field must be zero-padded from byte 12");
        }
    }

    @Test
    @DisplayName("Should round-trip a GCM message between mirrored contexts")
    void testEncryptDecryptRoundTripGCM() throws Exception {
        // This only passes if the decrypt side truncates the 16-byte nonce field
        // to the 12 bytes AES-GCM actually uses - a full-length IV derives a
        // different J0 and fails authentication.
        // The AES-CCM round-trip is added once the CCM path moves to JCE.
        byte[] message = "round trip across the transform header".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        // the peer's encryption key is our decryption key and vice versa
        Smb2EncryptionContext sender = new Smb2EncryptionContext(Smb2EncryptionContext.CIPHER_AES_128_GCM, DialectVersion.SMB311,
                testEncryptionKey, testDecryptionKey);
        Smb2EncryptionContext receiver = new Smb2EncryptionContext(Smb2EncryptionContext.CIPHER_AES_128_GCM, DialectVersion.SMB311,
                testDecryptionKey, testEncryptionKey);

        byte[] encrypted = sender.encryptMessage(message, 0xAABBL);
        byte[] decrypted = receiver.decryptMessage(encrypted);
        org.junit.jupiter.api.Assertions.assertArrayEquals(message, decrypted, "GCM round-trip should return the plaintext");
    }

    @Test
    @DisplayName("Should generate multiple unique nonces")
    void testGenerateMultipleNonces() {
        // Given
        int count = 100;
        java.util.Set<String> nonceSet = new java.util.HashSet<>();

        // When
        for (int i = 0; i < count; i++) {
            byte[] nonce = encryptionContext.generateNonce();
            String nonceHex = bytesToHex(nonce);
            nonceSet.add(nonceHex);
        }

        // Then
        assertEquals(count, nonceSet.size(), "All generated nonces should be unique");
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}