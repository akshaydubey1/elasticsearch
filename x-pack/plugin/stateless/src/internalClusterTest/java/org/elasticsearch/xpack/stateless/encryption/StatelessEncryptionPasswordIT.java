/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.stateless.encryption;

import org.apache.logging.log4j.core.LogEvent;
import org.apache.lucene.tests.util.LuceneTestCase;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.coordination.JoinHelper;
import org.elasticsearch.cluster.coordination.JoinValidationService;
import org.elasticsearch.cluster.coordination.stateless.StoreHeartbeatService;
import org.elasticsearch.cluster.metadata.ReservedStateMetadata;
import org.elasticsearch.common.Priority;
import org.elasticsearch.common.settings.MockSecureSettings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.core.Strings;
import org.elasticsearch.core.TimeValue;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.reservedstate.service.FileSettingsService;
import org.elasticsearch.test.ESIntegTestCase;
import org.elasticsearch.test.MockLog;
import org.elasticsearch.xpack.encryption.EncryptionPlugin;
import org.elasticsearch.xpack.encryption.PasswordPekEncryption;
import org.elasticsearch.xpack.stateless.AbstractStatelessPluginIntegTestCase;
import org.elasticsearch.xpack.stateless.settings.secure.SecureSettingsPlugin;
import org.junit.Before;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.elasticsearch.xpack.encryption.EncryptionPasswordTestUtil.ACTIVE_PASSWORD_ID_KEY;
import static org.elasticsearch.xpack.encryption.EncryptionPasswordTestUtil.PASSWORD_KEY_PREFIX;
import static org.elasticsearch.xpack.encryption.EncryptionPasswordTestUtil.canWrapForDisk;
import static org.elasticsearch.xpack.encryption.EncryptionPasswordTestUtil.hasUsableKey;
import static org.elasticsearch.xpack.encryption.EncryptionPasswordTestUtil.keyPasswordId;
import static org.elasticsearch.xpack.encryption.EncryptionPasswordTestUtil.keyUnwrapFailed;
import static org.hamcrest.Matchers.equalTo;

/**
 * On stateless only master-eligible nodes persist cluster state, so only they must be able to wrap the cluster state encryption key.
 * When the password comes from cluster secrets every node gets it from the cluster state, so nodes are not checked for it; otherwise each
 * node uses the password in its own keystore, which may differ between nodes.
 *
 * <p>Nodes start without a password. Keystore passwords are added with a secure settings reload, so that a restart drops them.
 */
@LuceneTestCase.SuppressFileSystems("*")
// not auto-managed, so that starting a master-eligible node that is rejected at join doesn't wait for it to join
@ESIntegTestCase.ClusterScope(scope = ESIntegTestCase.Scope.TEST, numDataNodes = 0, numClientNodes = 0, autoManageMasterNodes = false)
public class StatelessEncryptionPasswordIT extends AbstractStatelessPluginIntegTestCase {

    @Before
    public void bootstrapFirstMaster() {
        internalCluster().setBootstrapMasterNodeIndex(0);
    }

    @Override
    protected Collection<Class<? extends Plugin>> nodePlugins() {
        Collection<Class<? extends Plugin>> plugins = new ArrayList<>(super.nodePlugins());
        plugins.add(EncryptionPlugin.class);
        plugins.add(SecureSettingsPlugin.class);
        return plugins;
    }

    /** A master-eligible node without a password at startup joins, since it gets the password from cluster secrets once it has joined. */
    public void testNodeWithoutPasswordJoinsWhenPasswordIsInClusterSecrets() throws Exception {
        startMasterOnlyNode();
        startIndexNode();
        startSearchNode();
        ensureStableCluster(3);
        applyClusterSecrets(1, ACTIVE_PASSWORD_ID_KEY, "v1", PASSWORD_KEY_PREFIX + "v1", "password-v1");
        assertBusy(() -> assertTrue(hasUsableKey(masterState())));

        String joining = startMasterOnlyNode();
        ensureStableCluster(4);
        assertBusy(() -> assertTrue(canWrapForDisk(pekEncryption(joining))));
        assertThat(pekEncryption(joining).activePasswordId(), equalTo("v1"));
        assertTrue(hasUsableKey(masterState()));

        createIndex("index-after-join");
        ensureGreen("index-after-join");
    }

    /**
     * Cluster secrets that switch to a new password and drop the old one are applied on every node, although the elected master's
     * persisted copy of the key is still wrapped with the old one: cluster secrets are the source of truth.
     */
    public void testClusterSecretsReplacingThePasswordAreAppliedOnEveryNode() throws Exception {
        startMasterOnlyNode();
        startMasterOnlyNode();
        startIndexNode();
        startSearchNode();
        ensureStableCluster(4);
        applyClusterSecrets(1, ACTIVE_PASSWORD_ID_KEY, "v1", PASSWORD_KEY_PREFIX + "v1", "password-v1");
        assertBusy(() -> assertThat(keyPasswordId(masterState()), equalTo("v1")));

        applyClusterSecrets(2, ACTIVE_PASSWORD_ID_KEY, "v2", PASSWORD_KEY_PREFIX + "v2", "password-v2");
        for (String node : internalCluster().getNodeNames()) {
            assertThat(node, pekEncryption(node).activePasswordId(), equalTo("v2"));
            assertTrue(node, canWrapForDisk(pekEncryption(node)));
        }
        assertTrue(hasUsableKey(masterState()));
        // the key metadata follows the new password although the old one is gone
        assertBusy(() -> assertThat(keyPasswordId(masterState()), equalTo("v2")));

        createIndex("index-after-password-change");
        ensureGreen("index-after-password-change");
    }

    /**
     * With keystore passwords, a master-eligible node without one can't join once the key is installed, while index and search nodes,
     * which don't persist cluster state, need none. A master-eligible node with a password of its own joins, and when it takes over as
     * master it persists the key it already holds with that password: it doesn't read the copy the previous master wrapped.
     */
    public void testMasterEligibleNodeWithoutKeystorePasswordCannotJoin() throws Exception {
        Settings fastFailover = Settings.builder()
            .put(StoreHeartbeatService.MAX_MISSED_HEARTBEATS.getKey(), 1)
            .put(StoreHeartbeatService.HEARTBEAT_FREQUENCY.getKey(), TimeValue.timeValueSeconds(1))
            .build();
        // otherwise the join is validated against the cached state from the index node's join, which has no key yet
        String master = startMasterOnlyNode(
            Settings.builder()
                .put(fastFailover)
                .put(JoinValidationService.JOIN_VALIDATION_CACHE_TIMEOUT_SETTING.getKey(), TimeValue.timeValueMillis(1))
                .build()
        );
        String indexNode = startIndexNode();
        ensureStableCluster(2);
        // the index node has no password, and the key is installed anyway
        reload(master, passwordSettings("v1", "password-v1"));
        assertBusy(() -> assertTrue(hasUsableKey(masterState())));

        String searchNode = startSearchNode();
        String secondIndexNode = startIndexNode();
        ensureStableCluster(4);

        String joining;
        try (MockLog mockLog = MockLog.capture(JoinHelper.class)) {
            mockLog.addExpectation(new JoinRejectedExpectation());
            joining = startMasterOnlyNode(fastFailover);
            mockLog.awaitAllExpectationsMatched();
        }
        // asked on the master: a random node may be the rejected one, which has no master
        assertEquals(4, internalCluster().clusterService(master).state().nodes().size());

        // the node retries joining, and is admitted once it can persist the key, with a password of its own
        reload(joining, passwordSettings("v2", "password-v2"));
        ensureStableCluster(5);
        assertTrue(hasUsableKey(masterState()));

        internalCluster().stopNode(master);
        assertBusy(() -> {
            ClusterState state = internalCluster().clusterService(joining).state();
            assertTrue(state.nodes().isLocalNodeElectedMaster());
            assertTrue(hasUsableKey(state));
        }, 30, TimeUnit.SECONDS);
        createIndex("index-after-failover");
        ensureGreen("index-after-failover");

        // stopped because the test framework's teardown writes cluster state as if to disk on a random node
        for (String node : List.of(indexNode, secondIndexNode, searchNode)) {
            internalCluster().stopNode(node);
        }
    }

    /** The elected master restarts without its password, so it holds no key; it restores the key once its password is reloaded. */
    public void testRestartedMasterRestoresKeyOnceItHasThePassword() throws Exception {
        String master = startMasterOnlyNode(
            Settings.builder()
                .put(StoreHeartbeatService.MAX_MISSED_HEARTBEATS.getKey(), 1)
                .put(StoreHeartbeatService.HEARTBEAT_FREQUENCY.getKey(), TimeValue.timeValueSeconds(1))
                .build()
        );
        reload(master, passwordSettings("v1", "password-v1"));
        assertBusy(() -> assertTrue(hasUsableKey(masterState())));

        internalCluster().restartNode(master);
        assertBusy(() -> assertTrue(keyUnwrapFailed(masterState())));

        reload(master, passwordSettings("v1", "password-v1"));
        assertBusy(() -> assertTrue(hasUsableKey(masterState())));
    }

    /** Writes file settings holding the given cluster secrets, as alternating names and values, and waits for every node to apply them. */
    private static void applyClusterSecrets(long version, String... namesAndValues) throws Exception {
        FileSettingsService fileSettings = internalCluster().getInstance(FileSettingsService.class, internalCluster().getMasterName());
        assertBusy(() -> assertTrue(fileSettings.watching()));
        StringBuilder secrets = new StringBuilder();
        for (int i = 0; i < namesAndValues.length; i += 2) {
            secrets.append(i == 0 ? "" : ",")
                .append('"')
                .append(namesAndValues[i])
                .append("\":\"")
                .append(namesAndValues[i + 1])
                .append('"');
        }
        String json = Strings.format("""
            {
                "metadata": {
                    "version": "%s",
                    "compatibility": "8.4.0"
                },
                "state": {
                    "cluster_secrets": {
                        "string_secrets": {%s}
                    }
                }
            }""", version, secrets);
        Files.createDirectories(fileSettings.watchedFileDir());
        Path tempFile = createTempFile();
        Files.writeString(tempFile, json);
        Files.move(tempFile, fileSettings.watchedFile(), StandardCopyOption.ATOMIC_MOVE);

        assertBusy(() -> {
            ReservedStateMetadata reserved = masterState().metadata().reservedStateMetadata().get(FileSettingsService.NAMESPACE);
            assertNotNull(reserved);
            assertEquals(version, reserved.version().longValue());
        });
        // every node has applied the cluster secrets, and so reloaded them, once the master has no pending tasks
        clusterAdmin().prepareHealth(TEST_REQUEST_TIMEOUT).setWaitForEvents(Priority.LANGUID).get();
    }

    private static ClusterState masterState() {
        return internalCluster().clusterService(internalCluster().getMasterName()).state();
    }

    private static PasswordPekEncryption pekEncryption(String node) {
        return internalCluster().getInstance(PasswordPekEncryption.class, node);
    }

    private static Settings passwordSettings(String passwordId, String password) {
        MockSecureSettings secure = new MockSecureSettings();
        secure.setString(ACTIVE_PASSWORD_ID_KEY, passwordId);
        secure.setString(PASSWORD_KEY_PREFIX + passwordId, password);
        return Settings.builder().setSecureSettings(secure).build();
    }

    private static void reload(String node, Settings settings) {
        findPlugin(node, EncryptionPlugin.class).reload(settings);
    }

    /** The joining node rejects the cluster's join validation, and logs the reason the master sends back. */
    private static class JoinRejectedExpectation implements MockLog.LoggingExpectation {
        private final CountDownLatch seen = new CountDownLatch(1);

        @Override
        public void match(LogEvent event) {
            for (Throwable t = event.getThrown(); t != null; t = t.getCause()) {
                if (t.getMessage() != null && t.getMessage().contains("this node cannot join the cluster")) {
                    seen.countDown();
                }
            }
        }

        @Override
        public void assertMatched() {
            assertEquals("expected the join to be rejected", 0, seen.getCount());
        }

        @Override
        public void awaitMatched(long millis) throws InterruptedException {
            assertTrue("expected the join to be rejected", seen.await(millis, TimeUnit.MILLISECONDS));
        }
    }
}
