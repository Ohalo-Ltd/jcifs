/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Properties;
import java.util.Random;

import org.codelibs.jcifs.smb.context.BaseContext;
import org.codelibs.jcifs.smb.impl.NtlmPasswordAuthenticator;
import org.codelibs.jcifs.smb.impl.SmbFile;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Integration tests against a Samba server that requires SMB 3.x channel
 * encryption ({@code smb encrypt = required}, {@code server min protocol = SMB3_00}).
 *
 * Every conversation against this fixture must be encrypted on the wire: the
 * server refuses cleartext operation after session setup, so a passing test
 * proves the client actually negotiated encryption, derived working keys and
 * framed transform-header messages correctly in both directions. This is the
 * harness whose absence hid the defects tracked in codelibs/jcifs#70 and
 * codelibs/jcifs#71.
 */
@Testcontainers(disabledWithoutDocker = true)
public class Smb3EncryptionIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(Smb3EncryptionIntegrationTest.class);

    private static final String USER = "encuser";
    private static final String PASSWORD = "enctest123";
    private static final String SHARE = "enc";

    /**
     * The fixture is built rather than pulled so the Samba version is pinned by
     * the base image. This matters: the SMB 3.1.1 AES-256 ciphers only exist in
     * Samba 4.15 and later, so an older server silently negotiates AES-128 and
     * leaves {@code AES-256-GCM} - the first entry in the client's default
     * preference order, and therefore the cipher most real servers select -
     * completely untested. Alpine 3.21 ships Samba 4.20.
     */
    private static final String DOCKERFILE = """
            FROM alpine:3.21
            RUN apk add --no-cache samba-server samba-common-tools
            COPY smb.conf /etc/samba/smb.conf
            COPY entrypoint.sh /entrypoint.sh
            RUN chmod +x /entrypoint.sh
            EXPOSE 445
            ENTRYPOINT ["/entrypoint.sh"]
            """;

    private static final String SMB_CONF = """
            [global]
               workgroup = WORKGROUP
               server string = jcifs encryption fixture
               security = user
               passdb backend = tdbsam
               map to guest = never
               disable netbios = yes
               smb ports = 445
               logging = stdout
               log level = 1
               server min protocol = SMB3_00
               smb encrypt = required
               server smb3 encryption algorithms = AES-256-GCM AES-128-GCM AES-256-CCM AES-128-CCM

            [enc]
               path = /share/enc
               browseable = yes
               read only = no
               guest ok = no
               valid users = encuser
            """;

    private static final String ENTRYPOINT = """
            #!/bin/sh
            set -e
            mkdir -p /share/enc
            chmod 0777 /share/enc
            adduser -D -H -s /sbin/nologin SMBUSER 2>/dev/null || true
            printf 'SMBPASS\\nSMBPASS\\n' | smbpasswd -a -s SMBUSER
            exec smbd --foreground --no-process-group --debug-stdout
            """.replace("SMBUSER", USER).replace("SMBPASS", PASSWORD);

    @Container
    private static final GenericContainer<?> sambaContainer =
            new GenericContainer<>(new ImageFromDockerfile("jcifs-samba-enc", false).withFileFromString("Dockerfile", DOCKERFILE)
                    .withFileFromString("smb.conf", SMB_CONF)
                    .withFileFromString("entrypoint.sh", ENTRYPOINT)).withExposedPorts(445)
                            .waitingFor(Wait.forLogMessage(".*smbd version.*started.*\\n", 1).withStartupTimeout(Duration.ofSeconds(180)))
                            .withLogConsumer(new Slf4jLogConsumer(log).withPrefix("SAMBA-ENC"));

    private static String sambaHost;
    private static int sambaPort;

    @BeforeAll
    static void setupContainer() throws Exception {
        sambaHost = sambaContainer.getHost();
        sambaPort = sambaContainer.getMappedPort(445);
        log.info("Encrypting Samba container started at {}:{}", sambaHost, sambaPort);

        // Wait a bit for Samba to fully initialize after ports are open
        Thread.sleep(5000);
    }

    /**
     * Creates a context that offers SMB 3.x encryption within the given dialect range.
     *
     * @param minVersion minimum dialect, e.g. "SMB300"
     * @param maxVersion maximum dialect, e.g. "SMB311"
     * @param encryptionEnabled whether to advertise encryption support
     * @return a configured context
     */
    private static CIFSContext createContext(final String minVersion, final String maxVersion, final boolean encryptionEnabled)
            throws CIFSException {
        return createContext(minVersion, maxVersion, encryptionEnabled, null);
    }

    /**
     * Creates a context that offers SMB 3.x encryption within the given dialect range.
     *
     * @param minVersion minimum dialect, e.g. "SMB300"
     * @param maxVersion maximum dialect, e.g. "SMB311"
     * @param encryptionEnabled whether to advertise encryption support
     * @param ciphers cipher list to offer, or null for the default preference order
     * @return a configured context
     */
    private static CIFSContext createContext(final String minVersion, final String maxVersion, final boolean encryptionEnabled,
            final String ciphers) throws CIFSException {
        final Properties props = new Properties();
        props.setProperty("jcifs.client.minVersion", minVersion);
        props.setProperty("jcifs.client.maxVersion", maxVersion);
        props.setProperty("jcifs.client.encryptionEnabled", String.valueOf(encryptionEnabled));
        if (ciphers != null) {
            props.setProperty("jcifs.client.encryptionCiphers", ciphers);
        }

        final BaseContext context = new BaseContext(new org.codelibs.jcifs.smb.config.PropertyConfiguration(props));
        return context.withCredentials(new NtlmPasswordAuthenticator(USER, PASSWORD));
    }

    private static String shareUrl(final String path) {
        return String.format("smb://%s:%d/%s/%s", sambaHost, sambaPort, SHARE, path);
    }

    private static void writeFile(final CIFSContext ctx, final String url, final byte[] content) throws Exception {
        try (SmbFile f = new SmbFile(url, ctx)) {
            try (OutputStream os = f.openOutputStream()) {
                os.write(content);
            }
        }
    }

    private static byte[] readFile(final CIFSContext ctx, final String url) throws Exception {
        try (SmbFile f = new SmbFile(url, ctx)) {
            try (InputStream is = f.openInputStream()) {
                return is.readAllBytes();
            }
        }
    }

    /**
     * @return deterministic pseudo-random test data of the given size
     */
    private static byte[] testData(final int size) {
        final byte[] data = new byte[size];
        new Random(0x534D42L).nextBytes(data);
        return data;
    }

    @Test
    void testEncryptedConversationSmb311() throws Exception {
        // SMB 3.1.1 negotiates AES-128-GCM by default
        final CIFSContext ctx = createContext("SMB311", "SMB311", true);
        final byte[] content = "encrypted over SMB 3.1.1".getBytes(StandardCharsets.UTF_8);
        writeFile(ctx, shareUrl("enc311.txt"), content);
        assertArrayEquals(content, readFile(ctx, shareUrl("enc311.txt")), "Encrypted SMB 3.1.1 round-trip should preserve content");
    }

    @Test
    void testEncryptedConversationSmb300() throws Exception {
        // SMB 3.0 has no cipher negotiation and always uses AES-128-CCM
        final CIFSContext ctx = createContext("SMB300", "SMB300", true);
        final byte[] content = "encrypted over SMB 3.0".getBytes(StandardCharsets.UTF_8);
        writeFile(ctx, shareUrl("enc300.txt"), content);
        assertArrayEquals(content, readFile(ctx, shareUrl("enc300.txt")), "Encrypted SMB 3.0 round-trip should preserve content");
    }

    @ParameterizedTest(name = "SMB 3.1.1 over {0}")
    @ValueSource(strings = { "AES-128-CCM", "AES-128-GCM", "AES-256-CCM", "AES-256-GCM" })
    void testEachNegotiatedCipher(final String cipher) throws Exception {
        // Pin the offered cipher so every algorithm gets exercised against a real
        // server, rather than only whichever one the server happens to prefer.
        // The AES-256 variants use a 32-byte key (L=256 in the SP800-108 KDF) and
        // are otherwise only covered by self-consistent round-trip unit tests,
        // which cannot detect a wire-format deviation.
        final CIFSContext ctx = createContext("SMB311", "SMB311", true, cipher);
        final byte[] content = ("encrypted with " + cipher).getBytes(StandardCharsets.UTF_8);
        final String url = shareUrl("cipher-" + cipher + ".txt");
        writeFile(ctx, url, content);
        assertArrayEquals(content, readFile(ctx, url), cipher + " round-trip should preserve content");
    }

    @Test
    void testMultiFrameRead() throws Exception {
        // Spans several read/write frames (negotiated maxima are < 64k), so this
        // exercises transform-header framing on consecutive messages in both
        // directions and the buffer-size accounting for encrypted frames.
        final CIFSContext ctx = createContext("SMB300", "SMB311", true);
        final byte[] content = testData(300 * 1024);
        writeFile(ctx, shareUrl("large.bin"), content);
        assertArrayEquals(content, readFile(ctx, shareUrl("large.bin")), "Multi-frame encrypted read should return the written data");
    }

    @Test
    void testCompoundRequest() throws Exception {
        // exists() issues a compound create/query-info/close chain on SMB2+, so
        // the whole compound must be encrypted as a single transform blob
        final CIFSContext ctx = createContext("SMB300", "SMB311", true);
        writeFile(ctx, shareUrl("compound.txt"), "x".getBytes(StandardCharsets.UTF_8));
        try (SmbFile f = new SmbFile(shareUrl("compound.txt"), ctx)) {
            assertTrue(f.exists(), "Compound create/query-info/close should succeed over encryption");
            assertEquals(1, f.length(), "File length should be readable over encryption");
        }
    }

    @Test
    void testDirectoryEnumeration() throws Exception {
        final CIFSContext ctx = createContext("SMB300", "SMB311", true);
        // openOutputStream does not create intermediate directories, so the
        // directory must exist before files are written into it
        try (SmbFile dir = new SmbFile(shareUrl("dir/"), ctx)) {
            if (!dir.exists()) {
                dir.mkdirs();
            }
        }
        writeFile(ctx, shareUrl("dir/a.txt"), "a".getBytes(StandardCharsets.UTF_8));
        writeFile(ctx, shareUrl("dir/b.txt"), "b".getBytes(StandardCharsets.UTF_8));
        try (SmbFile dir = new SmbFile(shareUrl("dir/"), ctx)) {
            final String[] names = dir.list();
            assertEquals(2, names.length, "Directory enumeration should see both files");
        }
    }

    @Test
    void testClientWithoutEncryptionIsRejected() throws Exception {
        // Fixture sanity check: a client that does not offer encryption must be
        // refused by the server, otherwise this suite would prove nothing.
        final CIFSContext ctx = createContext("SMB300", "SMB311", false);
        assertThrows(CIFSException.class, () -> {
            try (SmbFile f = new SmbFile(shareUrl(""), ctx)) {
                f.list();
            }
        }, "Server requiring encryption should reject a cleartext-only client");
    }
}
