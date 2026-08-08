package org.codelibs.jcifs.smb.impl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicLong;

import org.codelibs.jcifs.smb.Address;
import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.DialectVersion;
import org.codelibs.jcifs.smb.SmbConstants;
import org.codelibs.jcifs.smb.SmbTransport;
import org.codelibs.jcifs.smb.internal.CommonServerMessageBlockRequest;
import org.codelibs.jcifs.smb.internal.SMBSigningDigest;
import org.codelibs.jcifs.smb.internal.SmbNegotiationResponse;
import org.codelibs.jcifs.smb.internal.smb1.com.ServerData;
import org.codelibs.jcifs.smb.internal.smb1.com.SmbComNegotiateResponse;
import org.codelibs.jcifs.smb.internal.smb2.Smb2Constants;
import org.codelibs.jcifs.smb.internal.smb2.Smb2EncryptionContext;
import org.codelibs.jcifs.smb.internal.smb2.nego.EncryptionNegotiateContext;
import org.codelibs.jcifs.smb.internal.smb2.nego.Smb2NegotiateResponse;
import org.codelibs.jcifs.smb.util.transport.Request;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SmbTransportImplTest {

    @Mock
    private CIFSContext ctx;
    @Mock
    private Configuration cfg;
    @Mock
    private Address address;

    private SmbTransportImpl transport;

    @BeforeEach
    void setUp() throws Exception {
        when(ctx.getConfig()).thenReturn(cfg);
        when(cfg.isSigningEnforced()).thenReturn(false);
        when(cfg.getSessionTimeout()).thenReturn(30_000);
        when(cfg.getResponseTimeout()).thenReturn(5_000);
        when(address.getHostAddress()).thenReturn("127.0.0.1");
        when(address.getHostName()).thenReturn("localhost");

        // Create the transport with safe defaults (no real sockets)
        transport = new SmbTransportImpl(ctx, address, 445, null, 0, false);

        // Reset MID to a known starting point for deterministic behavior
        setField(transport, "mid", new AtomicLong());
    }

    // Utility: reflectively set a private/protected field (searches up the hierarchy)
    private static void setField(Object target, String name, Object value) {
        try {
            Field f = findField(target.getClass(), name);
            f.setAccessible(true);
            f.set(target, value);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // Utility: reflectively get a private/protected field (searches up the hierarchy)
    private static Object getField(Object target, String name) {
        try {
            Field f = findField(target.getClass(), name);
            f.setAccessible(true);
            return f.get(target);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // Helper: find field in class hierarchy
    private static Field findField(Class<?> clazz, String name) throws NoSuchFieldException {
        Class<?> current = clazz;
        while (current != null) {
            try {
                return current.getDeclaredField(name);
            } catch (NoSuchFieldException e) {
                current = current.getSuperclass();
            }
        }
        throw new NoSuchFieldException(name);
    }

    @Test
    @DisplayName("getResponseTimeout returns override for SMB requests")
    void getResponseTimeout_override() {
        // Arrange
        CommonServerMessageBlockRequest req = mock(CommonServerMessageBlockRequest.class);
        when(req.getOverrideTimeout()).thenReturn(1234);

        // Act
        int timeout = transport.getResponseTimeout(req);

        // Assert
        assertEquals(1234, timeout);
    }

    @Test
    @DisplayName("getResponseTimeout falls back to config for non-SMB requests")
    void getResponseTimeout_default() {
        // Arrange
        Request req = mock(Request.class);
        when(cfg.getResponseTimeout()).thenReturn(2222);

        // Act & Assert
        assertEquals(2222, transport.getResponseTimeout(req));
    }

    @Test
    @DisplayName("Basic getters: address, hostName, inflight, sessions")
    void basicGetters() {
        assertEquals(address, transport.getRemoteAddress());
        assertNull(transport.getRemoteHostName(), "tconHostName starts null");
        assertEquals(0, transport.getInflightRequests());
        assertEquals(0, transport.getNumSessions());
    }

    @Test
    @DisplayName("isDisconnected / isFailed reflect socket and state")
    void connectionStateChecks() throws Exception {
        // Arrange: simulate connected state and open socket
        setField(transport, "state", 3); // connected
        Socket s = mock(Socket.class);
        when(s.isClosed()).thenReturn(false);
        setField(transport, "socket", s);

        // Act & Assert
        assertFalse(transport.isDisconnected());
        assertFalse(transport.isFailed());

        // Close socket -> both should be true
        when(s.isClosed()).thenReturn(true);
        assertTrue(transport.isDisconnected());
        assertTrue(transport.isFailed());
    }

    @Test
    @DisplayName("capability query delegates to negotiation state")
    void hasCapability_delegates() throws Exception {
        // Arrange
        SmbNegotiationResponse nego = mock(SmbNegotiationResponse.class);
        setField(transport, "negotiated", nego);
        when(nego.haveCapabilitiy(SmbConstants.CAP_DFS)).thenReturn(true);

        // Act & Assert
        assertTrue(transport.hasCapability(SmbConstants.CAP_DFS));
        verify(nego, times(1)).haveCapabilitiy(SmbConstants.CAP_DFS);
    }

    @Test
    @DisplayName("SMB version detection via flag or response type")
    void isSMB2_variants() throws Exception {
        // 1) smb2 flag set
        setField(transport, "smb2", true);
        assertTrue(transport.isSMB2());

        // 2) smb2 false but negotiated is SMB2 response
        setField(transport, "smb2", false);
        Smb2NegotiateResponse smb2 = new Smb2NegotiateResponse(cfg);
        setField(transport, "negotiated", smb2);
        assertTrue(transport.isSMB2());

        // 3) SMB1 negotiation
        SmbComNegotiateResponse smb1 = new SmbComNegotiateResponse(ctx);
        setField(transport, "negotiated", smb1);
        assertFalse(transport.isSMB2());
    }

    @Test
    @DisplayName("Digest setter/getter roundtrip")
    void digestRoundtrip() {
        SMBSigningDigest dg = mock(SMBSigningDigest.class);
        transport.setDigest(dg);
        assertSame(dg, transport.getDigest());
    }

    @Test
    @DisplayName("Context accessor returns constructor-provided context")
    void contextAccessor() {
        assertSame(ctx, transport.getContext());
    }

    @Test
    @DisplayName("acquire returns same instance")
    void acquireReturnsSameInstance() {
        SmbTransportImpl acquired = transport.acquire();
        assertSame(transport, acquired);
        transport.close(); // release once
    }

    @Test
    @DisplayName("Server encryption key is returned for SMB1 negotiation only")
    void serverEncryptionKey() {
        // No negotiation yet -> null
        assertNull(transport.getServerEncryptionKey());

        // SMB1 negotiation with server data
        SmbComNegotiateResponse smb1 = new SmbComNegotiateResponse(ctx);
        ServerData sd = smb1.getServerData();
        sd.encryptionKey = new byte[] { 1, 2, 3 };
        setField(transport, "negotiated", smb1);
        assertArrayEquals(new byte[] { 1, 2, 3 }, transport.getServerEncryptionKey());

        // SMB2 negotiation never exposes key via this API
        setField(transport, "negotiated", new Smb2NegotiateResponse(cfg));
        assertNull(transport.getServerEncryptionKey());
    }

    @Test
    @DisplayName("Signing enforced/optional adhere to flags and negotiation")
    void signingModes() throws Exception {
        // Enforced via constructor flag -> optional false, enforced true regardless of negotiation
        SmbTransportImpl enforced = new SmbTransportImpl(ctx, address, 445, null, 0, true);
        assertFalse(enforced.isSigningOptional());
        assertTrue(enforced.isSigningEnforced());

        // Negotiated required -> enforced true; negotiated enabled-only -> optional true
        SmbNegotiationResponse nego = mock(SmbNegotiationResponse.class);
        setField(transport, "negotiated", nego);
        when(nego.isSigningNegotiated()).thenReturn(true);
        when(nego.isSigningRequired()).thenReturn(false).thenReturn(true);

        assertTrue(transport.isSigningOptional());
        assertTrue(transport.isSigningEnforced());
    }

    @Test
    @DisplayName("unwrap returns this for compatible types and throws otherwise")
    void unwrapBehavior() {
        // Happy paths
        SmbTransport asIface = transport.unwrap(SmbTransport.class);
        assertSame(transport, asIface);
        SmbTransportInternal asInternal = transport.unwrap(SmbTransportInternal.class);
        assertSame(transport, asInternal);

        // Invalid type should throw
        class OtherTransport implements SmbTransport {
            @Override
            public String getRemoteHostName() {
                return "test";
            }

            @Override
            public Address getRemoteAddress() {
                return mock(Address.class);
            }

            @Override
            public CIFSContext getContext() {
                return mock(CIFSContext.class);
            }

            @Override
            public <T extends SmbTransport> T unwrap(Class<T> type) {
                if (type.isInstance(this)) {
                    return type.cast(this);
                }
                throw new ClassCastException("Cannot unwrap to " + type.getName());
            }

            @Override
            public void close() {
                // no-op for test
            }
        }
        assertThrows(ClassCastException.class, () -> transport.unwrap(OtherTransport.class));
    }

    @Test
    @DisplayName("getSmbSession creates and then reuses matching session")
    void getSmbSession_createAndReuse() {
        // Arrange: minimal credentials chain so SmbSessionImpl constructor succeeds
        CredentialsInternal creds = mock(CredentialsInternal.class);
        when(ctx.getCredentials()).thenReturn(creds);
        when(creds.unwrap(CredentialsInternal.class)).thenReturn(creds);
        when(creds.clone()).thenReturn(creds);

        assertEquals(0, transport.getNumSessions());

        // Act: create new session (happy path)
        SmbSessionImpl s1 = transport.getSmbSession(ctx);
        assertNotNull(s1);
        assertEquals(1, transport.getNumSessions());
        s1.close();

        // Act: request again with same context -> reuse existing
        SmbSessionImpl s2 = transport.getSmbSession(ctx);
        assertNotNull(s2);
        assertEquals(1, transport.getNumSessions(), "Should reuse existing session");
        s2.close();
    }

    @Test
    @DisplayName("DFS referrals: invalid double-slash prefix triggers exception")
    void dfsReferrals_invalidPath() {
        CIFSException ex = assertThrows(CIFSException.class, () -> transport.getDfsReferrals(ctx, "\\\\server\\share", null, null, 1));
        assertTrue(ex.getMessage().contains("double slash"));
    }

    @Nested
    @MockitoSettings(strictness = Strictness.LENIENT)
    class PreauthHashAndEncryption {
        @Test
        @DisplayName("calculatePreauthHash rejects non-SMB2 or missing negotiation")
        void preauthHash_rejectsWhenUnsupported() {
            // Not SMB2
            assertThrows(SmbUnsupportedOperationException.class, () -> transport.calculatePreauthHash(new byte[] { 1 }, 0, 1, null));

            // SMB2 flag set but no negotiation
            setField(transport, "smb2", true);
            assertThrows(SmbUnsupportedOperationException.class, () -> transport.calculatePreauthHash(new byte[] { 1 }, 0, 1, null));
        }

        @Test
        @DisplayName("calculatePreauthHash rejects dialects before SMB 3.1.1")
        void preauthHash_rejectsOldDialect() {
            setField(transport, "smb2", true);
            Smb2NegotiateResponse nego = new Smb2NegotiateResponse(cfg);
            // selectedDialect: SMB300
            setField(nego, "selectedDialect", DialectVersion.SMB300);
            setField(transport, "negotiated", nego);
            assertThrows(SmbUnsupportedOperationException.class, () -> transport.calculatePreauthHash(new byte[] { 1, 2, 3 }, 0, 3, null));
        }

        @Test
        @DisplayName("calculatePreauthHash computes SHA-512 chain for SMB 3.1.1")
        void preauthHash_happyPath() throws Exception {
            setField(transport, "smb2", true);
            Smb2NegotiateResponse nego = new Smb2NegotiateResponse(cfg);
            setField(nego, "selectedDialect", DialectVersion.SMB311);
            setField(nego, "selectedPreauthHash", 1); // 1 => SHA-512
            setField(transport, "negotiated", nego);

            byte[] input = new byte[] { 10, 20, 30, 40 };
            byte[] hash1 = transport.calculatePreauthHash(input, 0, input.length, null);
            assertNotNull(hash1);
            assertEquals(64, hash1.length, "SHA-512 size");

            byte[] hash2 = transport.calculatePreauthHash(new byte[] { 50 }, 0, 1, hash1);
            assertNotNull(hash2);
            assertEquals(64, hash2.length);
            assertNotEquals(new String(hash1), new String(hash2), "Chained hash should differ");
        }

        @Test
        @DisplayName("createEncryptionContext rejects when SMB2/3 not negotiated")
        void createEncryptionContext_rejects_noNegotiation() {
            assertThrows(SmbUnsupportedOperationException.class, () -> transport.createEncryptionContext(new byte[] { 1 }, null));
        }

        @Test
        @DisplayName("createEncryptionContext rejects pre-SMB3 dialect")
        void createEncryptionContext_rejects_oldDialect() throws Exception {
            setField(transport, "smb2", true);
            Smb2NegotiateResponse nego = new Smb2NegotiateResponse(cfg);
            setField(nego, "selectedDialect", DialectVersion.SMB210);
            setField(transport, "negotiated", nego);
            assertThrows(SmbUnsupportedOperationException.class, () -> transport.createEncryptionContext(new byte[] { 1, 2, 3, 4 }, null));
        }

        @Test
        @DisplayName("createEncryptionContext rejects a null or empty session key with a clear error")
        void createEncryptionContext_rejects_missingSessionKey() throws Exception {
            setField(transport, "smb2", true);
            Smb2NegotiateResponse nego = new Smb2NegotiateResponse(cfg);
            setField(nego, "selectedDialect", DialectVersion.SMB311);
            setField(transport, "negotiated", nego);

            // e.g. anonymous sessions have no session key; the failure must be an
            // SmbUnsupportedOperationException, not the KDF's IllegalArgumentException
            // ("A KDF requires Ki (a seed) as input", refs codelibs/jcifs#70)
            assertThrows(SmbUnsupportedOperationException.class, () -> transport.createEncryptionContext(null, new byte[64]));
            assertThrows(SmbUnsupportedOperationException.class, () -> transport.createEncryptionContext(new byte[0], new byte[64]));
        }

        @Test
        @DisplayName("createEncryptionContext selects AES-CCM for SMB 3.0 and AES-GCM for SMB 3.1.1")
        void createEncryptionContext_happyDialects() throws Exception {
            byte[] sessionKey = new byte[16];
            byte[] preauth = new byte[16];

            // SMB 3.0 -> AES-128-CCM
            setField(transport, "smb2", true);
            Smb2NegotiateResponse smb300 = new Smb2NegotiateResponse(cfg);
            setField(smb300, "selectedDialect", DialectVersion.SMB300);
            setField(transport, "negotiated", smb300);
            Smb2EncryptionContext ccm = transport.createEncryptionContext(sessionKey, preauth);
            assertEquals(EncryptionNegotiateContext.CIPHER_AES128_CCM, ccm.getCipherId());
            assertEquals(DialectVersion.SMB300, ccm.getDialect());

            // SMB 3.1.1 -> default AES-128-GCM when server did not choose
            Smb2NegotiateResponse smb311 = new Smb2NegotiateResponse(cfg);
            setField(smb311, "selectedDialect", DialectVersion.SMB311);
            setField(smb311, "selectedCipher", -1);
            setField(transport, "negotiated", smb311);
            Smb2EncryptionContext gcm = transport.createEncryptionContext(sessionKey, preauth);
            assertEquals(EncryptionNegotiateContext.CIPHER_AES128_GCM, gcm.getCipherId());
            assertEquals(DialectVersion.SMB311, gcm.getDialect());
        }

        @Test
        @DisplayName("encryptionContextFor resolves a registered session's context by session ID")
        void encryptionContextLookup() {
            SmbSessionImpl sess = mock(SmbSessionImpl.class);
            Smb2EncryptionContext ectx = new Smb2EncryptionContext(EncryptionNegotiateContext.CIPHER_AES128_GCM, DialectVersion.SMB311,
                    new byte[16], new byte[16]);
            when(sess.getEncryptionContext()).thenReturn(ectx);

            transport.registerSession(7L, sess);
            assertSame(ectx, transport.encryptionContextFor(7L));
            assertNull(transport.encryptionContextFor(8L), "Unknown session IDs must resolve to null");

            transport.unregisterSession(7L);
            assertNull(transport.encryptionContextFor(7L), "Unregistered sessions must resolve to null");
        }

        @Test
        @DisplayName("session ID zero is never registered")
        void sessionIdZeroNotRegistered() {
            SmbSessionImpl sess = mock(SmbSessionImpl.class);
            transport.registerSession(0L, sess);
            assertNull(transport.encryptionContextFor(0L), "Session ID 0 (not yet established) must not be registered");
        }
    }

    @Nested
    @DisplayName("Encrypted send path")
    class EncryptedSend {

        private static final long SESSION_ID = 0x11223344L;

        private java.io.ByteArrayOutputStream out;
        private Smb2EncryptionContext peerCtx;

        @BeforeEach
        void setUpEncryptedTransport() {
            out = new java.io.ByteArrayOutputStream();
            setField(transport, "smb2", true);
            setField(transport, "out", out);
            when(ctx.getBufferCache()).thenReturn(new BufferCacheImpl(8, 0x10000 + 128));

            byte[] k1 = new byte[16];
            byte[] k2 = new byte[16];
            java.util.Arrays.fill(k1, (byte) 1);
            java.util.Arrays.fill(k2, (byte) 2);
            Smb2EncryptionContext sendCtx =
                    new Smb2EncryptionContext(EncryptionNegotiateContext.CIPHER_AES128_GCM, DialectVersion.SMB311, k1, k2);
            // the peer decrypts with mirrored keys
            peerCtx = new Smb2EncryptionContext(EncryptionNegotiateContext.CIPHER_AES128_GCM, DialectVersion.SMB311, k2, k1);

            SmbSessionImpl sess = mock(SmbSessionImpl.class);
            when(sess.getEncryptionContext()).thenReturn(sendCtx);
            // session-level encryption requirement: encrypt on every tree
            when(sess.getEncryptionContextFor(org.mockito.ArgumentMatchers.anyInt())).thenReturn(sendCtx);
            transport.registerSession(SESSION_ID, sess);
        }

        private byte[] decryptWire(byte[] wire) throws Exception {
            int nbssLen = (wire[1] & 0xFF) << 16 | (wire[2] & 0xFF) << 8 | wire[3] & 0xFF;
            assertEquals(wire.length - 4, nbssLen, "NBSS length must cover the whole transform frame");
            assertEquals((byte) 0xFD, wire[4], "Encrypted frames start with the transform protocol ID");
            assertEquals((byte) 'S', wire[5]);
            assertEquals((byte) 'M', wire[6]);
            assertEquals((byte) 'B', wire[7]);
            return peerCtx.decryptMessage(java.util.Arrays.copyOfRange(wire, 4, wire.length));
        }

        @Test
        @DisplayName("doSend encrypts a session-bound message into a transform frame")
        void doSend_encrypts() throws Exception {
            org.codelibs.jcifs.smb.internal.smb2.Smb2EchoRequest req = new org.codelibs.jcifs.smb.internal.smb2.Smb2EchoRequest(cfg);
            req.setSessionId(SESSION_ID);

            transport.doSend(req);

            byte[] plain = decryptWire(out.toByteArray());
            assertEquals((byte) 0xFE, plain[0], "Decrypted payload must be a regular SMB2 message");
            assertEquals(0x0D, org.codelibs.jcifs.smb.util.Encdec.dec_uint16le(plain, 12), "Command must be ECHO");
            assertEquals(SESSION_ID, org.codelibs.jcifs.smb.util.Encdec.dec_uint64le(plain, 40), "Session ID must be preserved");
            assertEquals(0,
                    org.codelibs.jcifs.smb.util.Encdec.dec_uint32le(plain, 16)
                            & org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2.SMB2_FLAGS_SIGNED,
                    "Encrypted messages must not carry the SIGNED flag");
        }

        @Test
        @DisplayName("doSend never signs an encrypted message")
        void doSend_suppressesSigning() throws Exception {
            org.codelibs.jcifs.smb.internal.smb2.Smb2EchoRequest req = new org.codelibs.jcifs.smb.internal.smb2.Smb2EchoRequest(cfg);
            req.setSessionId(SESSION_ID);
            org.codelibs.jcifs.smb.internal.smb2.Smb2SigningDigest digest =
                    mock(org.codelibs.jcifs.smb.internal.smb2.Smb2SigningDigest.class);
            req.setDigest(digest);

            transport.doSend(req);

            verify(digest, org.mockito.Mockito.never()).sign(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.anyInt(),
                    org.mockito.ArgumentMatchers.anyInt(), org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
            assertNull(req.getDigest(), "The digest must be cleared on the encrypted path");
        }

        @Test
        @DisplayName("doSend leaves SESSION_SETUP and unknown sessions in cleartext")
        void doSend_cleartextExemptions() throws Exception {
            // SESSION_SETUP carrying an interim session ID stays cleartext
            org.codelibs.jcifs.smb.internal.smb2.Smb2EchoRequest setup = new org.codelibs.jcifs.smb.internal.smb2.Smb2EchoRequest(cfg);
            setup.setCommand(0x01); // SMB2_SESSION_SETUP
            setup.setSessionId(SESSION_ID);
            transport.doSend(setup);
            assertEquals((byte) 0xFE, out.toByteArray()[4], "SESSION_SETUP must never be encrypted");

            // a session without encryption context stays cleartext
            out.reset();
            org.codelibs.jcifs.smb.internal.smb2.Smb2EchoRequest other = new org.codelibs.jcifs.smb.internal.smb2.Smb2EchoRequest(cfg);
            other.setSessionId(0x999L);
            transport.doSend(other);
            assertEquals((byte) 0xFE, out.toByteArray()[4], "Sessions without encryption context send cleartext");
        }

        @Test
        @DisplayName("doSend encrypts a compound chain as one transform blob")
        void doSend_encryptsCompoundChain() throws Exception {
            org.codelibs.jcifs.smb.internal.smb2.Smb2EchoRequest first = new org.codelibs.jcifs.smb.internal.smb2.Smb2EchoRequest(cfg);
            org.codelibs.jcifs.smb.internal.smb2.Smb2EchoRequest second = new org.codelibs.jcifs.smb.internal.smb2.Smb2EchoRequest(cfg);
            first.chain(second);
            first.setSessionId(SESSION_ID);

            transport.doSend(first);

            byte[] wire = out.toByteArray();
            byte[] plain = decryptWire(wire);
            int nextCommand = org.codelibs.jcifs.smb.util.Encdec.dec_uint32le(plain, 20);
            assertTrue(nextCommand > 0, "The compound chain must be present in one plaintext blob");
            assertEquals(0x0D, org.codelibs.jcifs.smb.util.Encdec.dec_uint16le(plain, nextCommand + 12),
                    "The chained command must follow at the NextCommand offset");
            // exactly one frame was written for the whole chain
            int nbssLen = (wire[1] & 0xFF) << 16 | (wire[2] & 0xFF) << 8 | wire[3] & 0xFF;
            assertEquals(wire.length, 4 + nbssLen, "The chain must be framed as a single encrypted message");
        }
    }

    @Nested
    @DisplayName("Encrypted receive path")
    class EncryptedReceive {

        private static final long SESSION_ID = 0x55667788L;

        private Smb2EncryptionContext serverCtx;

        @BeforeEach
        void setUpEncryptedTransport() {
            setField(transport, "smb2", true);
            setField(transport, "negotiated", new Smb2NegotiateResponse(cfg));
            when(cfg.getMaximumBufferSize()).thenReturn(0x10000);
            when(ctx.getBufferCache()).thenReturn(new BufferCacheImpl(8, 0x10000 + 128));

            byte[] k1 = new byte[16];
            byte[] k2 = new byte[16];
            java.util.Arrays.fill(k1, (byte) 3);
            java.util.Arrays.fill(k2, (byte) 4);
            Smb2EncryptionContext clientCtx =
                    new Smb2EncryptionContext(EncryptionNegotiateContext.CIPHER_AES128_GCM, DialectVersion.SMB311, k1, k2);
            // the server encrypts server-to-client traffic with the client's decryption key
            serverCtx = new Smb2EncryptionContext(EncryptionNegotiateContext.CIPHER_AES128_GCM, DialectVersion.SMB311, k2, k1);

            SmbSessionImpl sess = mock(SmbSessionImpl.class);
            when(sess.getEncryptionContext()).thenReturn(clientCtx);
            transport.registerSession(SESSION_ID, sess);
        }

        /**
         * Hand-crafts a plaintext SMB2 ECHO response message.
         *
         * @param mid message ID
         * @param nextCommandOffset compound offset of the next message, 0 for the last
         * @return encoded message (68 bytes, or nextCommandOffset with padding)
         */
        private byte[] plainEchoResponse(long mid, int nextCommandOffset) {
            byte[] msg = new byte[nextCommandOffset > 0 ? nextCommandOffset : 68];
            System.arraycopy(org.codelibs.jcifs.smb.internal.util.SMBUtil.SMB2_HEADER, 0, msg, 0, 64);
            org.codelibs.jcifs.smb.internal.util.SMBUtil.writeInt2(0x0D, msg, 12); // ECHO
            org.codelibs.jcifs.smb.internal.util.SMBUtil
                    .writeInt4(org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2.SMB2_FLAGS_SERVER_TO_REDIR, msg, 16);
            org.codelibs.jcifs.smb.internal.util.SMBUtil.writeInt4(nextCommandOffset, msg, 20);
            org.codelibs.jcifs.smb.internal.util.SMBUtil.writeInt8(mid, msg, 24);
            org.codelibs.jcifs.smb.internal.util.SMBUtil.writeInt8(SESSION_ID, msg, 40);
            org.codelibs.jcifs.smb.internal.util.SMBUtil.writeInt2(4, msg, 64); // echo response structure size
            return msg;
        }

        /** Wraps a plaintext message into an NBSS-framed encrypted wire frame. */
        private byte[] encryptedWire(byte[] plain, long sessionId) throws Exception {
            byte[] frame = serverCtx.encryptMessage(plain, sessionId);
            byte[] wire = new byte[4 + frame.length];
            wire[1] = (byte) (frame.length >> 16 & 0xFF);
            wire[2] = (byte) (frame.length >> 8 & 0xFF);
            wire[3] = (byte) (frame.length & 0xFF);
            System.arraycopy(frame, 0, wire, 4, frame.length);
            return wire;
        }

        private void feed(byte[]... wires) {
            java.io.ByteArrayOutputStream all = new java.io.ByteArrayOutputStream();
            for (byte[] w : wires) {
                all.writeBytes(w);
            }
            setField(transport, "in", new java.io.ByteArrayInputStream(all.toByteArray()));
        }

        @Test
        @DisplayName("peekKey decrypts a transform frame and returns the inner MessageId")
        void peekKey_decrypts() throws Exception {
            feed(encryptedWire(plainEchoResponse(42L, 0), SESSION_ID));

            Long key = transport.peekKey();

            assertEquals(42L, key, "The MessageId must come from the decrypted header");

            org.codelibs.jcifs.smb.internal.smb2.Smb2EchoResponse resp = new org.codelibs.jcifs.smb.internal.smb2.Smb2EchoResponse(cfg);
            transport.doRecv(resp);
            assertTrue(resp.isReceived(), "The response must decode from the buffered plaintext");
            assertNull(getField(transport, "pendingPlaintext"), "The buffered plaintext must be cleared after receive");
        }

        @Test
        @DisplayName("a compound response decodes entirely from one decrypted blob")
        void doRecv_compoundFromPlaintext() throws Exception {
            byte[] first = plainEchoResponse(50L, 72); // 68 bytes padded to the 8-byte boundary
            byte[] second = plainEchoResponse(51L, 0);
            byte[] plain = new byte[first.length + second.length];
            System.arraycopy(first, 0, plain, 0, first.length);
            System.arraycopy(second, 0, plain, first.length, second.length);
            feed(encryptedWire(plain, SESSION_ID));

            assertEquals(50L, transport.peekKey());

            org.codelibs.jcifs.smb.internal.smb2.Smb2EchoResponse r1 = new org.codelibs.jcifs.smb.internal.smb2.Smb2EchoResponse(cfg);
            org.codelibs.jcifs.smb.internal.smb2.Smb2EchoResponse r2 = new org.codelibs.jcifs.smb.internal.smb2.Smb2EchoResponse(cfg);
            setField(r1, "next", r2);
            transport.doRecv(r1);

            assertTrue(r1.isReceived(), "First compound response must decode");
            assertTrue(r2.isReceived(), "Chained compound response must decode from the same plaintext blob");
        }

        @Test
        @DisplayName("a corrupted auth tag fails loudly instead of surfacing a message")
        void peekKey_rejectsCorruptedFrame() throws Exception {
            byte[] wire = encryptedWire(plainEchoResponse(42L, 0), SESSION_ID);
            wire[4 + 4] ^= (byte) 0xFF; // flip a signature byte
            feed(wire);

            assertThrows(java.io.IOException.class, () -> transport.peekKey(), "An unauthentic frame must raise");
        }

        @Test
        @DisplayName("an unknown session ID fails loudly")
        void peekKey_rejectsUnknownSession() throws Exception {
            feed(encryptedWire(plainEchoResponse(42L, 0), 0x424242L));

            assertThrows(java.io.IOException.class, () -> transport.peekKey(),
                    "Encrypted frames for unknown sessions must raise, not fall back to cleartext");
        }

        @Test
        @DisplayName("an OriginalMessageSize not matching the frame fails loudly")
        void peekKey_rejectsSizeMismatch() throws Exception {
            byte[] wire = encryptedWire(plainEchoResponse(42L, 0), SESSION_ID);
            // patch the OriginalMessageSize field (frame offset 36)
            org.codelibs.jcifs.smb.internal.util.SMBUtil.writeInt4(9999, wire, 4 + 36);
            feed(wire);

            assertThrows(java.io.IOException.class, () -> transport.peekKey(),
                    "MS-SMB2 3.2.5.1.1.1 requires discarding frames whose size does not match");
        }

        @Test
        @DisplayName("doSkip discards an unmatched decrypted frame without desynchronizing the stream")
        void doSkip_discardsBufferedPlaintext() throws Exception {
            byte[] encrypted = encryptedWire(plainEchoResponse(77L, 0), SESSION_ID);
            // followed by a cleartext frame that must still parse correctly
            byte[] clearMsg = plainEchoResponse(78L, 0);
            byte[] clearWire = new byte[4 + clearMsg.length];
            clearWire[2] = (byte) (clearMsg.length >> 8 & 0xFF);
            clearWire[3] = (byte) (clearMsg.length & 0xFF);
            System.arraycopy(clearMsg, 0, clearWire, 4, clearMsg.length);
            feed(encrypted, clearWire);

            assertEquals(77L, transport.peekKey());
            transport.doSkip(77L);
            assertNull(getField(transport, "pendingPlaintext"), "Skipping must drop the buffered plaintext");

            assertEquals(78L, transport.peekKey(), "The following cleartext frame must still be readable");
        }
    }

    @Test
    @DisplayName("getRequestSecurityMode honors enforced and server-required flags")
    void requestSecurityMode() {
        // Not enforced, server does not require -> enabled only
        Smb2NegotiateResponse first = mock(Smb2NegotiateResponse.class);
        when(first.isSigningRequired()).thenReturn(false);
        assertEquals(Smb2Constants.SMB2_NEGOTIATE_SIGNING_ENABLED, transport.getRequestSecurityMode(first));

        // Enforced -> required+enabled
        SmbTransportImpl enforced = new SmbTransportImpl(ctx, address, 445, null, 0, true);
        assertEquals(Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED | Smb2Constants.SMB2_NEGOTIATE_SIGNING_ENABLED,
                enforced.getRequestSecurityMode(first));

        // Server indicates required -> required+enabled
        Smb2NegotiateResponse firstReq = mock(Smb2NegotiateResponse.class);
        when(firstReq.isSigningRequired()).thenReturn(true);
        assertEquals(Smb2Constants.SMB2_NEGOTIATE_SIGNING_REQUIRED | Smb2Constants.SMB2_NEGOTIATE_SIGNING_ENABLED,
                transport.getRequestSecurityMode(firstReq));
    }

    @Test
    @DisplayName("toString contains key fields without throwing")
    void toStringContainsInfo() {
        String s = transport.toString();
        assertNotNull(s);
        assertTrue(s.contains("state="));
        assertTrue(s.contains(":445"));
    }
}
