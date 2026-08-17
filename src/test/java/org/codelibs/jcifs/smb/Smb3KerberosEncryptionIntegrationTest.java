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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Random;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosTicket;

import org.codelibs.jcifs.smb.config.PropertyConfiguration;
import org.codelibs.jcifs.smb.context.BaseContext;
import org.codelibs.jcifs.smb.impl.JAASAuthenticator;
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
import org.testcontainers.containers.wait.strategy.WaitAllStrategy;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Integration tests for SMB 3.1.1 channel encryption over <em>Kerberos</em>
 * authentication, against a Samba Active Directory domain controller that
 * requires encryption ({@code smb encrypt = required}) and refuses NTLM
 * outright ({@code ntlm auth = disabled}).
 *
 * The Kerberos part is the entire point. NTLM session keys are always exactly
 * 16 bytes, so {@code Session.SessionKey} and {@code Session.FullSessionKey} of
 * MS-SMB2 3.1.4.2 coincide and the distinction between them - the truncated key
 * for signing, the untruncated key for the AES-256 ciphers - cannot be
 * observed. A Kerberos AES256 session key is 32 bytes, so a client that derives
 * its AES-256 encryption keys from the truncated key produces keys the server
 * cannot reproduce. The server then silently discards the first encrypted
 * request and the client waits for a response that never comes.
 *
 * This is the harness for that defect: the NTLM fixture in
 * {@link Smb3EncryptionIntegrationTest} passes every cipher either way and
 * structurally cannot catch it.
 */
@Testcontainers(disabledWithoutDocker = true)
public class Smb3KerberosEncryptionIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(Smb3KerberosEncryptionIntegrationTest.class);

    private static final String REALM = "JCIFS.TEST";
    private static final String NETBIOS_DOMAIN = "JCIFS";
    private static final String DC_HOSTNAME = "jcifsdc";
    private static final String USER = "encuser";
    private static final String PASSWORD = "Encrypt3d!Pass";
    private static final String ADMIN_PASSWORD = "Encrypt3d!Admin";
    private static final String SHARE = "enc";

    /**
     * Anything below this and the KDC hands out an RC4 ticket, whose 16-byte
     * session key would hide exactly the defect under test.
     */
    private static final int ETYPE_AES256_CTS_HMAC_SHA1_96 = 18;

    private static final String DOCKERFILE = """
            FROM debian:bookworm-slim
            ENV DEBIAN_FRONTEND=noninteractive
            RUN apt-get update && apt-get install -y --no-install-recommends \\
                    samba samba-ad-provision samba-dsdb-modules samba-vfs-modules winbind \\
                    smbclient krb5-user ldb-tools \\
                && rm -rf /var/lib/apt/lists/*
            COPY provision.sh /provision.sh
            RUN chmod +x /provision.sh && /provision.sh
            COPY entrypoint.sh /entrypoint.sh
            RUN chmod +x /entrypoint.sh
            EXPOSE 88 445
            ENTRYPOINT ["/entrypoint.sh"]
            """;

    /**
     * Provisioning runs at image build time so container startup is a plain
     * daemon start. {@code posix:eadb} keeps the NT ACLs in a tdb rather than
     * {@code security.*} xattrs, which an unprivileged container filesystem
     * cannot write - without it the sysvol ACL step of the provision aborts.
     */
    private static final String PROVISION = """
            #!/bin/sh
            set -ex

            rm -f /etc/samba/smb.conf
            samba-tool domain provision \\
                --use-rfc2307 \\
                --realm=REALM_PLACEHOLDER \\
                --domain=DOMAIN_PLACEHOLDER \\
                --server-role=dc \\
                --dns-backend=SAMBA_INTERNAL \\
                --host-name=HOST_PLACEHOLDER \\
                --adminpass='ADMINPASS_PLACEHOLDER' \\
                --option="posix:eadb=/var/lib/samba/private/eadb.tdb"

            cp -f /var/lib/samba/private/krb5.conf /etc/krb5.conf

            # Require encryption everywhere and refuse NTLM, so a passing test
            # cannot have quietly fallen back to a 16-byte NTLM session key.
            sed -i '/^\\[global\\]/a\\
            \\tserver min protocol = SMB3_00\\
            \\tsmb encrypt = required\\
            \\tserver smb3 encryption algorithms = AES-256-GCM AES-128-GCM AES-256-CCM AES-128-CCM\\
            \\tntlm auth = disabled\\
            \\tposix:eadb = /var/lib/samba/private/eadb.tdb\\
            \\tlog level = 1\\
            \\tlogging = stdout' /etc/samba/smb.conf

            cat >> /etc/samba/smb.conf <<EOF

            [SHARE_PLACEHOLDER]
            \tpath = /share/enc
            \tread only = no
            \tguest ok = no
            EOF

            mkdir -p /share/enc
            chmod 0777 /share/enc

            samba-tool user create USER_PLACEHOLDER 'USERPASS_PLACEHOLDER' --given-name=Enc --surname=User

            # The client reaches the DC through a mapped port on localhost, so the
            # ticket it asks for is cifs/localhost. Mapping that SPN onto the DC's
            # own machine account is enough - every SPN of an account shares the
            # account's long-term key, so smbd accepts the ticket with no extra
            # keytab.
            samba-tool spn add "cifs/localhost" "HOSTUPPER_PLACEHOLDER\\$"

            testparm -s >/dev/null
            """.replace("REALM_PLACEHOLDER", REALM)
            .replace("DOMAIN_PLACEHOLDER", NETBIOS_DOMAIN)
            .replace("HOSTUPPER_PLACEHOLDER", DC_HOSTNAME.toUpperCase())
            .replace("HOST_PLACEHOLDER", DC_HOSTNAME)
            .replace("ADMINPASS_PLACEHOLDER", ADMIN_PASSWORD)
            .replace("SHARE_PLACEHOLDER", SHARE)
            .replace("USERPASS_PLACEHOLDER", PASSWORD)
            .replace("USER_PLACEHOLDER", USER);

    private static final String ENTRYPOINT = """
            #!/bin/sh
            set -e
            echo "127.0.0.1 HOST_PLACEHOLDER.REALMLOWER_PLACEHOLDER HOST_PLACEHOLDER" >> /etc/hosts
            echo "nameserver 127.0.0.1" > /etc/resolv.conf
            exec samba --foreground --no-process-group --debug-stdout
            """.replace("REALMLOWER_PLACEHOLDER", REALM.toLowerCase()).replace("HOST_PLACEHOLDER", DC_HOSTNAME);

    @Container
    private static final GenericContainer<?> dcContainer =
            new GenericContainer<>(new ImageFromDockerfile("jcifs-samba-dc", false).withFileFromString("Dockerfile", DOCKERFILE)
                    .withFileFromString("provision.sh", PROVISION)
                    .withFileFromString("entrypoint.sh", ENTRYPOINT)).withCreateContainerCmdModifier(cmd -> cmd.withHostName(DC_HOSTNAME))
                            .withExposedPorts(88, 445)
                            .waitingFor(new WaitAllStrategy().withStrategy(Wait.forLogMessage(".*samba version.*started.*\\n", 1))
                                    .withStrategy(Wait.forListeningPort())
                                    .withStartupTimeout(Duration.ofMinutes(5)))
                            .withLogConsumer(new Slf4jLogConsumer(log).withPrefix("SAMBA-DC"));

    private static String dcHost;
    private static int smbPort;

    @BeforeAll
    static void setupContainer() throws Exception {
        dcHost = dcContainer.getHost();
        smbPort = dcContainer.getMappedPort(445);
        final int kdcPort = dcContainer.getMappedPort(88);
        log.info("Samba AD DC started, SMB at {}:{}, KDC at {}:{}", dcHost, smbPort, dcHost, kdcPort);

        // The KDC is reachable only on a mapped TCP port, so pin it explicitly
        // and force TCP - a mapped port has no UDP counterpart. Restricting the
        // enctypes to AES256 keeps the session key at the 32 bytes this test is
        // about instead of leaving it to KDC preference.
        final Path krb5Conf = Files.createTempFile("jcifs-krb5", ".conf");
        krb5Conf.toFile().deleteOnExit();
        Files.writeString(krb5Conf, """
                [libdefaults]
                    default_realm = %s
                    dns_lookup_realm = false
                    dns_lookup_kdc = false
                    udp_preference_limit = 1
                    rdns = false
                    default_tkt_enctypes = aes256-cts-hmac-sha1-96
                    default_tgs_enctypes = aes256-cts-hmac-sha1-96
                    permitted_enctypes = aes256-cts-hmac-sha1-96

                [realms]
                    %s = {
                        kdc = %s:%d
                    }
                """.formatted(REALM, REALM, dcHost, kdcPort));
        System.setProperty("java.security.krb5.conf", krb5Conf.toString());

        waitForKdc();
    }

    /**
     * The container's ports are open before the KDC will actually issue
     * tickets, so poll a real login until it succeeds.
     */
    private static void waitForKdc() throws Exception {
        Exception last = null;
        for (int i = 0; i < 60; i++) {
            try {
                final Subject subject = createAuthenticator().getSubject();
                if (subject != null && !subject.getPrivateCredentials(KerberosTicket.class).isEmpty()) {
                    log.info("KDC issued a TGT after {} attempt(s)", i + 1);
                    return;
                }
                last = new IllegalStateException("Login produced no ticket");
            } catch (final Exception e) {
                last = e;
            }
            Thread.sleep(1000);
        }
        throw new IllegalStateException("KDC did not become ready", last);
    }

    private static JAASAuthenticator createAuthenticator() {
        // A programmatic JAAS configuration keeps the fixture self-contained -
        // no jaas.conf on disk and no JVM-wide login configuration.
        final Map<String, String> options = new HashMap<>();
        options.put("storeKey", "true");
        options.put("refreshKrb5Config", "true");
        return new JAASAuthenticator(options, REALM, USER, PASSWORD);
    }

    /**
     * @param ciphers cipher list to offer, most preferred first
     * @return a Kerberos-authenticated context that demands encryption
     */
    private static CIFSContext createContext(final String ciphers) throws CIFSException {
        final Properties props = new Properties();
        props.setProperty("jcifs.client.minVersion", "SMB311");
        props.setProperty("jcifs.client.maxVersion", "SMB311");
        props.setProperty("jcifs.client.encryptionRequired", "true");
        props.setProperty("jcifs.client.encryptionCiphers", ciphers);
        // NTLM fallback would defeat the point of the fixture; the server
        // refuses NTLM anyway, but fail fast and locally rather than there
        props.setProperty("jcifs.allowNTLMFallback", "false");
        // a key the server cannot reproduce shows up as a hang, so keep the
        // wait short enough that a broken cipher fails the test quickly
        props.setProperty("jcifs.client.responseTimeout", "10000");
        props.setProperty("jcifs.client.soTimeout", "15000");

        final BaseContext context = new BaseContext(new PropertyConfiguration(props));
        return context.withCredentials(createAuthenticator());
    }

    private static String shareUrl(final String path) {
        return String.format("smb://%s:%d/%s/%s", dcHost, smbPort, SHARE, path);
    }

    private static byte[] testData(final int size) {
        final byte[] data = new byte[size];
        new Random(0x4B524235L).nextBytes(data);
        return data;
    }

    /**
     * Establishes the precondition the rest of the class depends on: the
     * Kerberos session key really is 32 bytes, so truncating it to 16 is
     * observable.
     */
    @Test
    void testKerberosSessionKeyIsAes256() throws Exception {
        final Subject subject = createAuthenticator().getSubject();
        assertNotNull(subject, "JAAS login failed");

        boolean sawTicket = false;
        for (final KerberosTicket ticket : subject.getPrivateCredentials(KerberosTicket.class)) {
            sawTicket = true;
            assertEquals(ETYPE_AES256_CTS_HMAC_SHA1_96, ticket.getSessionKeyType(), "expected an AES256 ticket for " + ticket.getServer());
            assertEquals(32, ticket.getSessionKey().getEncoded().length, "expected a 32-byte session key for " + ticket.getServer());
        }
        assertTrue(sawTicket, "no Kerberos ticket was issued");
    }

    /**
     * The core test: a full write/read round trip over each negotiable cipher.
     *
     * With a 32-byte Kerberos session key, AES-256-GCM and AES-256-CCM only
     * work if the encryption keys were derived from the untruncated key.
     */
    @ParameterizedTest(name = "SMB 3.1.1 over Kerberos with {0}")
    @ValueSource(strings = { "AES-128-CCM", "AES-128-GCM", "AES-256-CCM", "AES-256-GCM" })
    void testEachNegotiatedCipherOverKerberos(final String cipher) throws Exception {
        final CIFSContext ctx = createContext(cipher);
        final byte[] content = testData(4096);
        final String url = shareUrl("kerberos-" + cipher + ".bin");

        try (SmbFile f = new SmbFile(url, ctx)) {
            try (OutputStream os = f.openOutputStream()) {
                os.write(content);
            }
            try (InputStream is = f.openInputStream()) {
                assertArrayEquals(content, is.readAllBytes(), "round trip mismatch for " + cipher);
            }
            f.delete();
        }
    }

    /**
     * A payload large enough to span several encrypted frames, so the fix is
     * exercised beyond the first transform-header message.
     */
    @Test
    void testMultiFrameTransferWithAes256Gcm() throws Exception {
        final CIFSContext ctx = createContext("AES-256-GCM");
        final byte[] content = testData(2 * 1024 * 1024);
        final String url = shareUrl("kerberos-large.bin");

        try (SmbFile f = new SmbFile(url, ctx)) {
            try (OutputStream os = f.openOutputStream()) {
                os.write(content);
            }
            try (InputStream is = f.openInputStream()) {
                assertArrayEquals(content, is.readAllBytes());
            }
            f.delete();
        }
    }
}
