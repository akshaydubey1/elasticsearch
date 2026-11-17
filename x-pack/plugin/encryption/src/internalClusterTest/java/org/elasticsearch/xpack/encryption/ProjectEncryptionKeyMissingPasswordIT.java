/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.encryption;

import org.apache.logging.log4j.core.LogEvent;
import org.elasticsearch.cluster.coordination.JoinHelper;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.MockSecureSettings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.health.HealthIndicatorResult;
import org.elasticsearch.health.HealthStatus;
import org.elasticsearch.health.node.HealthInfo;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.plugins.PluginsService;
import org.elasticsearch.test.ESIntegTestCase;
import org.elasticsearch.test.MockLog;
import org.elasticsearch.test.NodeRoles;
import org.elasticsearch.xpack.encryption.spi.EncryptedData;
import org.elasticsearch.xpack.encryption.spi.EncryptionService;
import org.elasticsearch.xpack.encryption.spi.EncryptionServiceState;
import org.elasticsearch.xpack.encryption.spi.EncryptionServiceUnavailableException;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

/**
 * A master-eligible or data node that cannot persist the project encryption key cannot persist any cluster state, so once the key is
 * installed such a node is not allowed to join. Installing the key only once every such node can persist it is covered by
 * {@code MissingPasswordRolloutIT}. A node that cannot read the key on its disk still starts; if
 * it is elected master, it reads the key from its disk once it has the password, and if no node can read the key, a reset recovers the
 * cluster.
 *
 * <p>Passwords are added with a secure settings reload rather than at startup, so that a restart drops them.
 */
@ESIntegTestCase.ClusterScope(scope = ESIntegTestCase.Scope.TEST, numDataNodes = 0, autoManageMasterNodes = false)
public class ProjectEncryptionKeyMissingPasswordIT extends ESIntegTestCase {

    private static final String PASSWORD_ID = "v1";
    private static final String PASSWORD = "encryption-test-password";

    @Override
    protected Collection<Class<? extends Plugin>> nodePlugins() {
        Collection<Class<? extends Plugin>> plugins = new ArrayList<>(super.nodePlugins());
        plugins.add(EncryptionPlugin.class);
        return plugins;
    }

    /** Once the key is installed, a node without a password can't join, and the password can't be reloaded away. */
    public void testNodeWithoutPasswordCannotJoinOnceKeyIsInstalled() throws Exception {
        internalCluster().setBootstrapMasterNodeIndex(0);
        String master = internalCluster().startNode();
        reload(master, passwordSettings());
        assertBusy(() -> assertThat(pekOn(master), notNullValue()));

        String joining;
        try (MockLog mockLog = MockLog.capture(JoinHelper.class)) {
            mockLog.addExpectation(new JoinRejectedExpectation());
            joining = internalCluster().startNode(NodeRoles.dataOnlyNode());
            mockLog.awaitAllExpectationsMatched();
        }
        assertEquals(1, internalCluster().clusterService(master).state().nodes().size());

        IllegalArgumentException e = expectThrows(IllegalArgumentException.class, () -> reload(master, Settings.EMPTY));
        assertThat(e.getMessage(), containsString("keeping the previous settings"));

        // a coordinating-only node doesn't write cluster state to disk, so it doesn't need a password
        String coordinating = internalCluster().startNode(NodeRoles.noRoles());
        ensureStableCluster(2, master);
        // stopped because the test framework's teardown writes cluster state as if to disk on a random node
        internalCluster().stopNode(coordinating);

        // the node retries joining, and is admitted once it can persist the key
        reload(joining, passwordSettings());
        ensureStableCluster(2);
        assertBusy(() -> assertEquals(HealthStatus.GREEN, health(joining).status()));
    }

    /**
     * The master restarts without its password. Encryption is unavailable until its password is reloaded; it then reads the key from its
     * disk.
     */
    public void testElectedMasterWithoutKeyReadsItOnceItHasThePassword() throws Exception {
        internalCluster().setBootstrapMasterNodeIndex(0);
        String master = internalCluster().startNode();
        reload(master, passwordSettings());
        assertBusy(() -> assertThat(pekOn(master), notNullValue()));
        byte[] payload = "missing-password-payload".getBytes(StandardCharsets.UTF_8);
        EncryptedData encrypted = internalCluster().getInstance(EncryptionService.class, master).encrypt(payload);

        internalCluster().restartNode(master);
        assertTrue(pekOn(master).isUnwrapFailed());
        EncryptionServiceUnavailableException e = expectThrows(
            EncryptionServiceUnavailableException.class,
            () -> decryptOn(master, encrypted)
        );
        assertEquals(EncryptionServiceState.UNAVAILABLE_DECRYPTION_FAILED, e.serviceState());
        assertEquals(ProjectEncryptionKeyHealthIndicatorService.MASTER_HAS_NO_KEY, health(master).symptom());

        reload(master, passwordSettings());
        assertBusy(() -> assertFalse(pekOn(master).isUnwrapFailed()));
        assertArrayEquals(payload, decryptOn(master, encrypted));
    }

    /** No node can read the key: the cluster still forms, so that a reset can recover it. */
    public void testResetRecoversClusterWhereNoNodeCanReadTheKey() throws Exception {
        internalCluster().setBootstrapMasterNodeIndex(0);
        List<String> nodes = internalCluster().startNodes(2);
        ensureStableCluster(2);
        for (String node : nodes) {
            reload(node, passwordSettings());
        }
        assertBusy(() -> nodes.forEach(node -> assertThat(pekOn(node), notNullValue())), 30, TimeUnit.SECONDS);

        internalCluster().fullRestart();
        ensureStableCluster(2);
        for (String node : internalCluster().getNodeNames()) {
            assertTrue(pekOn(node).isUnwrapFailed());
        }

        client().execute(TransportEncryptionResetAction.TYPE, new EncryptionResetRequest(TEST_REQUEST_TIMEOUT, TEST_REQUEST_TIMEOUT, true))
            .get();
        for (String node : internalCluster().getNodeNames()) {
            assertBusy(() -> assertThat(pekOn(node), nullValue()));
        }

        for (String node : internalCluster().getNodeNames()) {
            reload(node, passwordSettings());
        }
        assertBusy(() -> {
            for (String node : internalCluster().getNodeNames()) {
                assertThat(pekOn(node), notNullValue());
                assertFalse(pekOn(node).isUnwrapFailed());
            }
        }, 30, TimeUnit.SECONDS);
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

    private static byte[] decryptOn(String node, EncryptedData encrypted) {
        return internalCluster().getInstance(EncryptionService.class, node).decrypt(encrypted);
    }

    private static Settings passwordSettings() {
        MockSecureSettings secure = new MockSecureSettings();
        secure.setString(ProjectEncryptionKeyPasswordSettings.ACTIVE_PASSWORD_ID_KEY, PASSWORD_ID);
        secure.setString(ProjectEncryptionKeyPasswordSettings.PASSWORD_PREFIX + PASSWORD_ID, PASSWORD);
        return Settings.builder().setSecureSettings(secure).build();
    }

    private static void reload(String node, Settings settings) {
        internalCluster().getInstance(PluginsService.class, node)
            .filterPlugins(EncryptionPlugin.class)
            .findFirst()
            .orElseThrow()
            .reload(settings);
    }

    private static ProjectEncryptionKeyMetadata pekOn(String node) {
        ClusterService clusterService = internalCluster().getInstance(ClusterService.class, node);
        return clusterService.state().metadata().getSingleProjectCustom(ProjectEncryptionKeyMetadata.TYPE);
    }

    private static HealthIndicatorResult health(String node) {
        return internalCluster().getInstance(ProjectEncryptionKeyHealthIndicatorService.class, node)
            .calculate(true, 10, HealthInfo.EMPTY_HEALTH_INFO);
    }
}
