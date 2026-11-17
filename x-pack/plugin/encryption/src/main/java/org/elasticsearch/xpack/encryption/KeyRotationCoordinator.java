/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.encryption;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRunnable;
import org.elasticsearch.action.support.RefCountingListener;
import org.elasticsearch.client.internal.Client;
import org.elasticsearch.cluster.ClusterChangedEvent;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.ClusterStateListener;
import org.elasticsearch.cluster.ClusterStateTaskListener;
import org.elasticsearch.cluster.LocalNodeMasterListener;
import org.elasticsearch.cluster.ProjectState;
import org.elasticsearch.cluster.SimpleBatchedExecutor;
import org.elasticsearch.cluster.metadata.Metadata;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.cluster.project.ProjectResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.cluster.service.MasterService;
import org.elasticsearch.cluster.service.MasterServiceTaskQueue;
import org.elasticsearch.common.Priority;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.AbstractRunnable;
import org.elasticsearch.core.Nullable;
import org.elasticsearch.core.TimeValue;
import org.elasticsearch.core.Tuple;
import org.elasticsearch.features.FeatureService;
import org.elasticsearch.gateway.GatewayService;
import org.elasticsearch.threadpool.Scheduler;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.xpack.encryption.spi.EncryptedData;
import org.elasticsearch.xpack.encryption.spi.EncryptedDataHandler;
import org.elasticsearch.xpack.encryption.spi.EncryptionService;

import java.io.Closeable;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Owns the PEK lifecycle on the elected master: installs the initial key, rotates the active key on a timer, updates
 * {@link ProjectEncryptionKeyMetadata#getPasswordId()} when the active password changes, drives registered
 * {@link EncryptedDataHandler}s to re-encrypt their data, and retires expired non-active keys.
 *
 * <p>Re-encryption uses a compute-then-CAS pattern: each handler re-encrypts against a cluster-state snapshot on the generic pool, then
 * a {@link ReEncryptApplyTask} atomically applies the result — aborting if the snapshot is stale. Conflicts retry on the next tick.
 */
class KeyRotationCoordinator implements LocalNodeMasterListener, Closeable {

    private static final Logger logger = LogManager.getLogger(KeyRotationCoordinator.class);

    // Number of check_intervals a non-active key persists after its deactivation time before retirement.
    private static final int GRACE_TICKS = 10;

    static final TimeValue INSTALL_RETRY_INTERVAL = TimeValue.timeValueSeconds(10);
    // lets the other nodes finish a cluster-wide secure settings reload before the master asks them again
    static final TimeValue RELOAD_INSTALL_RETRY_DELAY = TimeValue.timeValueSeconds(1);

    /**
     * How frequently the project encryption key is rotated. {@link TimeValue#ZERO} disables rotation.
     */
    static final Setting<TimeValue> ROTATION_INTERVAL_SETTING = Setting.timeSetting(
        "xpack.encryption.key_rotation.interval",
        TimeValue.timeValueDays(30),
        TimeValue.ZERO,
        Setting.Property.NodeScope
    );

    /**
     * How often the master polls to drive rotation forward (begin a new rotation if due, resume
     * an in-progress rotation, or retire old keys when handlers have all completed).
     */
    static final Setting<TimeValue> CHECK_INTERVAL_SETTING = Setting.timeSetting(
        "xpack.encryption.key_rotation.check_interval",
        TimeValue.timeValueHours(1),
        new Setting.Validator<>() {
            @Override
            public void validate(TimeValue value) {
                if (value.compareTo(TimeValue.timeValueSeconds(1)) < 0) {
                    throw new IllegalArgumentException(
                        "[xpack.encryption.key_rotation.check_interval] must be at least 1s, got [" + value + "]"
                    );
                }
            }

            @Override
            public void validate(TimeValue value, Map<Setting<?>, Object> settings) {
                TimeValue rotationInterval = (TimeValue) settings.get(ROTATION_INTERVAL_SETTING);
                if (rotationInterval.duration() > 0 && value.compareTo(rotationInterval) > 0) {
                    throw new IllegalArgumentException(
                        "[xpack.encryption.key_rotation.check_interval] ("
                            + value
                            + ") must not be greater than ["
                            + ROTATION_INTERVAL_SETTING.getKey()
                            + "] ("
                            + rotationInterval
                            + ")"
                    );
                }
            }

            @Override
            public Iterator<Setting<?>> settings() {
                return List.<Setting<?>>of(ROTATION_INTERVAL_SETTING).iterator();
            }
        },
        Setting.Property.NodeScope
    );

    private final ClusterService clusterService;
    private final ThreadPool threadPool;
    private final ProjectResolver projectResolver;
    private final FeatureService featureService;
    private final EncryptionService encryptionService;
    private final MasterServiceTaskQueue<KeyRotationTask> taskQueue;
    private final TimeValue rotationInterval;
    private final TimeValue checkInterval;
    private final List<EncryptedDataHandler<?>> handlers;
    private final ProjectEncryptionKeyMetadata.PekEncryption pekEncryption;
    private final ClusterStateListener clusterStateListener = this::onClusterStateChanged;
    private final Supplier<Settings> settingsSupplier;
    private final Client client;
    private final boolean stateless;

    private volatile Scheduler.Cancellable scheduledTask;
    private volatile boolean closed = false;
    private final AtomicBoolean reEncrypting = new AtomicBoolean(false);
    // held from the readiness check until the install is submitted or, if a node is not ready, until the retry
    private final AtomicBoolean installInFlight = new AtomicBoolean(false);
    private final AtomicBoolean beginRotationInFlight = new AtomicBoolean(false);
    private final AtomicBoolean passwordIdRotateInFlight = new AtomicBoolean(false);
    private final AtomicBoolean installRecheck = new AtomicBoolean(false);
    // set while an install retry is pending; whichever of the scheduled retry and an early one takes it releases the install
    private final AtomicReference<Object> pendingInstallRetry = new AtomicReference<>();
    // node names in the last "cannot persist it" warning, so it is logged only when they change
    private final AtomicReference<Set<String>> nodesWithoutPEKPassword = new AtomicReference<>();
    // one restore attempt per secure settings snapshot while master, since only a reload can make this node's copy readable
    private final AtomicReference<Settings> lastRestoreAttempt = new AtomicReference<>();

    static KeyRotationCoordinator create(
        ClusterService clusterService,
        ThreadPool threadPool,
        ProjectResolver projectResolver,
        FeatureService featureService,
        EncryptionService encryptionService,
        Collection<EncryptedDataHandler<?>> handlers,
        Supplier<Settings> settingsSupplier,
        ProjectEncryptionKeyMetadata.PekEncryption pekEncryption,
        Client client
    ) {
        KeyRotationCoordinator coordinator = new KeyRotationCoordinator(
            clusterService,
            threadPool,
            projectResolver,
            featureService,
            encryptionService,
            handlers,
            settingsSupplier,
            pekEncryption,
            client
        );
        clusterService.addLocalNodeMasterListener(coordinator);
        clusterService.addListener(coordinator.clusterStateListener);
        return coordinator;
    }

    KeyRotationCoordinator(
        ClusterService clusterService,
        ThreadPool threadPool,
        ProjectResolver projectResolver,
        FeatureService featureService,
        EncryptionService encryptionService,
        Collection<EncryptedDataHandler<?>> handlers,
        Supplier<Settings> settingsSupplier,
        ProjectEncryptionKeyMetadata.PekEncryption pekEncryption,
        Client client
    ) {
        this.client = client;
        this.clusterService = clusterService;
        this.threadPool = threadPool;
        this.projectResolver = projectResolver;
        this.featureService = featureService;
        this.encryptionService = encryptionService;
        this.handlers = new CopyOnWriteArrayList<>(handlers);
        this.stateless = DiscoveryNode.isStateless(clusterService.getSettings());
        this.taskQueue = clusterService.createTaskQueue(
            "project-encryption-key",
            Priority.NORMAL,
            new KeyRotationExecutor(projectResolver, pekEncryption, stateless)
        );
        Settings initialSettings = settingsSupplier.get();
        this.rotationInterval = ROTATION_INTERVAL_SETTING.get(initialSettings);
        this.checkInterval = CHECK_INTERVAL_SETTING.get(initialSettings);
        this.pekEncryption = pekEncryption;
        this.settingsSupplier = settingsSupplier;
    }

    /**
     * Triggers a password-id check on the generic thread pool after a secure-settings reload. This avoids a listener-ordering race where
     * {@link #onClusterStateChanged} fires before {@link EncryptionPlugin#reload} updates the shared settings supplier, causing the
     * mismatch to go undetected until the next periodic tick.
     */
    void reload() {
        threadPool.generic().execute(() -> {
            if (closed) return;
            Object retry = pendingInstallRetry.get();
            if (retry != null) {
                threadPool.schedule(() -> retryInstall(retry), RELOAD_INSTALL_RETRY_DELAY, threadPool.generic());
            }
            ClusterState state = clusterService.state();
            if (state.blocks().hasGlobalBlock(GatewayService.STATE_NOT_RECOVERED_BLOCK)
                || state.nodes().isLocalNodeElectedMaster() == false) {
                return;
            }
            checkPasswordId(state);
        });
    }

    @Override
    public void onMaster() {
        if (closed) {
            return;
        }
        startSchedule();
    }

    @Override
    public void offMaster() {
        if (closed) {
            return;
        }
        reEncrypting.set(false);
        lastRestoreAttempt.set(null);
        stopSchedule();
    }

    // package-private for testing
    void onClusterStateChanged(ClusterChangedEvent event) {
        if (closed) {
            return;
        }
        ClusterState state = event.state();
        if (state.blocks().hasGlobalBlock(GatewayService.STATE_NOT_RECOVERED_BLOCK)) {
            return;
        }
        ProjectEncryptionKeyMetadata.GatewayKeys gatewayKeys = pekEncryption.gatewayKeys();
        if (gatewayKeys != null && event.previousState().blocks().hasGlobalBlock(GatewayService.STATE_NOT_RECOVERED_BLOCK) == false) {
            ProjectEncryptionKeyMetadata previous = getCurrentMetadata(event.previousState());
            if (previous != null && getCurrentMetadata(state) == null) {
                gatewayKeys.clearIfActiveKey(previous.getActiveKeyId());
            }
        }
        if (event.localNodeMaster() == false) {
            return;
        }
        Object retry = pendingInstallRetry.get();
        if (retry != null
            && event.nodesChanged()
            && Stream.concat(event.nodesDelta().addedNodes().stream(), event.nodesDelta().removedNodes().stream())
                .anyMatch(node -> PasswordPekEncryption.persistsClusterState(node.getRoles(), stateless))) {
            threadPool.generic().execute(() -> retryInstall(retry));
            return;
        }
        checkPasswordId(state);
    }

    private void checkPasswordId(ClusterState state) {
        var metadata = getCurrentMetadata(state);
        String activePasswordId = ProjectEncryptionKeyPasswordSettings.getActivePasswordId(settingsSupplier.get());
        if (metadata == null) {
            if (activePasswordId != null
                && featureService.clusterHasFeature(state, ProjectEncryptionKeyService.PROJECT_ENCRYPTION_KEY_FEATURE)) {
                scheduleInstall(activePasswordId, state);
            }
            return;
        }
        if (metadata.isUnwrapFailed()) {
            scheduleRestore(metadata);
            return;
        }
        if (activePasswordId != null && activePasswordId.equals(metadata.getPasswordId()) == false) {
            schedulePasswordIdChange(metadata, activePasswordId);
        }
    }

    private void advanceKeyLifecycle(ProjectEncryptionKeyMetadata metadata, long now) {
        if (metadata.isUnwrapFailed()) {
            logger.debug("project encryption key: skipping lifecycle advancement in degraded state");
            return;
        }
        if (rotationDisabled()) {
            return;
        }
        long activeKeyAge = now - metadata.getGeneratedAt(metadata.getActiveKeyId());
        if (activeKeyAge >= rotationInterval.millis()) {
            logger.info("project encryption key due for rotation (active key generated {} ago)", TimeValue.timeValueMillis(activeKeyAge));
            submitBeginRotation();
        }
        long retireCutoff = now - GRACE_TICKS * checkInterval.millis();
        if (metadata.findRetireableKeyIds(retireCutoff).isEmpty() == false) {
            submitTaskIfOpen("retire-project-encryption-keys", new RetireKeysTask(retireCutoff, metadata.getActiveKeyId()));
        }
    }

    private boolean rotationDisabled() {
        return rotationInterval.duration() == 0;
    }

    private synchronized void startSchedule() {
        if (closed || scheduledTask != null) {
            return;
        }
        logger.debug("starting PEK lifecycle schedule (check_interval={}, rotation_interval={})", checkInterval, rotationInterval);
        scheduledTask = threadPool.scheduleWithFixedDelay(this::tick, checkInterval, threadPool.generic());
    }

    private synchronized void stopSchedule() {
        if (scheduledTask != null) {
            logger.debug("stopping PEK lifecycle schedule");
            scheduledTask.cancel();
            scheduledTask = null;
        }
    }

    void tick() {
        if (closed) {
            return;
        }
        ClusterState state = clusterService.state();
        if (state.blocks().hasGlobalBlock(GatewayService.STATE_NOT_RECOVERED_BLOCK) || state.nodes().isLocalNodeElectedMaster() == false) {
            return;
        }
        checkPasswordId(state);

        ProjectEncryptionKeyMetadata metadata = getCurrentMetadata(state);
        if (metadata == null || metadata.isUnwrapFailed()) {
            return;
        }
        long now = threadPool.absoluteTimeInMillis();
        var reEncryptionInProgress = reEncrypt(metadata);
        // In-flight ReEncryptApplyTasks would lose their CAS check if the active key rotated now.
        if (reEncryptionInProgress) {
            logger.debug("project encryption key: deferring lifecycle advancement; re-encryption still in progress");
            return;
        }

        advanceKeyLifecycle(metadata, now);
    }

    private boolean reEncrypt(ProjectEncryptionKeyMetadata metadata) {
        String activeKeyId = metadata.getActiveKeyId();
        List<EncryptedDataHandler<?>> pending = handlers.stream().filter(h -> metadata.isHandlerOnActive(h.customName()) == false).toList();
        if (pending.isEmpty()) {
            return false;
        }
        if (reEncrypting.compareAndSet(false, true) == false) {
            logger.warn("re-encryption already in progress, skipping this tick");
            return true;
        }
        try (
            var listeners = new RefCountingListener(
                ActionListener.runAfter(
                    ActionListener.wrap(unused -> {}, e -> logger.warn("re-encryption failed; will retry on next tick", e)),
                    () -> reEncrypting.set(false)
                )
            )
        ) {
            for (EncryptedDataHandler<?> handler : pending) {
                ActionListener<Void> l = listeners.acquire();
                threadPool.generic().execute(() -> dispatchOne(handler, activeKeyId, l));
            }
        }
        return true;
    }

    private <T extends Metadata.ProjectCustom> void dispatchOne(
        EncryptedDataHandler<T> handler,
        String expectedActiveKeyId,
        ActionListener<Void> listener
    ) {
        try {
            ClusterState snapshot = clusterService.state();
            ProjectState projectState = projectResolver.getProjectState(snapshot);

            T oldCustom = projectState.metadata().custom(handler.customName());
            UnaryOperator<EncryptedData> rewrapper = existing -> {
                if (existing.keyId().equals(expectedActiveKeyId)) {
                    return existing;
                }
                byte[] plaintext = encryptionService.decrypt(existing);
                try {
                    return encryptionService.encrypt(plaintext);
                } finally {
                    Arrays.fill(plaintext, (byte) 0);
                }
            };
            T newCustom = handler.reEncrypt(oldCustom, rewrapper);
            if (oldCustom != null && newCustom == null) {
                listener.onFailure(new IllegalStateException("Re-encrypting non-null state returned null state"));
                return;
            }

            assert newCustom == null || handler.customName().equals(newCustom.getWriteableName())
                : "handler ["
                    + handler.getClass().getSimpleName()
                    + "] customName="
                    + handler.customName()
                    + " does not match returned custom getWriteableName="
                    + newCustom.getWriteableName();
            var task = new ReEncryptApplyTask(handler.customName(), oldCustom, newCustom, expectedActiveKeyId, listener);
            if (submitTaskIfOpen("re-encrypt-" + handler.customName(), task) == false) {
                // we still need to complete the callback when the cluster is shutting down, otherwise we'll end up with a dangling listener
                listener.onResponse(null);
            }
        } catch (Exception e) {
            listener.onFailure(e);
        }
    }

    @Override
    public synchronized void close() {
        closed = true;
        clusterService.removeListener(clusterStateListener);
        stopSchedule();
    }

    private synchronized boolean submitTaskIfOpen(String source, KeyRotationTask task) {
        if (closed) {
            // do not submit new tasks when cluster is shutting down
            return false;
        }
        taskQueue.submitTask(source, task, null);
        return true;
    }

    // Visible for testing
    void register(EncryptedDataHandler<?> handler) {
        handlers.add(handler);
        logger.debug("registered encrypted-data handler [{}]", handler.getClass().getSimpleName());
    }

    @Nullable
    ProjectEncryptionKeyMetadata getCurrentMetadata(ClusterState state) {
        return projectResolver.getProjectState(state).metadata().custom(ProjectEncryptionKeyMetadata.TYPE);
    }

    private void scheduleInstall(String passwordId, ClusterState state) {
        // If a node joined during the installation, its install would be dropped (not all nodes are guaranteed to be able to wrap the PEK),
        // so check again once this one completes. Set before acquiring, so a holder that releases concurrently still sees it.
        installRecheck.set(true);
        if (installInFlight.compareAndSet(false, true) == false) {
            return;
        }
        installRecheck.set(false);
        if (ProjectEncryptionKeyPasswordSettings.hasPassword(settingsSupplier.get(), passwordId) == false) {
            installInFlight.set(false);
            logger.warn(
                "project encryption key install skipped: secure setting [{}{}] is not configured",
                ProjectEncryptionKeyPasswordSettings.PASSWORD_PREFIX,
                passwordId
            );
            return;
        }
        DiscoveryNode[] nodes = state.nodes()
            .getAllNodes()
            .stream()
            .filter(node -> PasswordPekEncryption.persistsClusterState(node.getRoles(), stateless))
            .toArray(DiscoveryNode[]::new);

        ActionListener<TransportCanPersistKeyAction.Response> listener = ActionListener.wrap(response -> {
            Set<String> ready = response.readyNodeIds();
            if (Arrays.stream(nodes).allMatch(node -> ready.contains(node.getId()))) {
                nodesWithoutPEKPassword.set(null);
                submitInstall(passwordId, ready);
                return;
            }
            Set<String> notReady = response.getNodes()
                .stream()
                .filter(r -> r.canPersist() == false)
                .map(r -> r.getNode().getName())
                .collect(Collectors.toCollection(TreeSet::new));
            if (notReady.isEmpty() == false && notReady.equals(this.nodesWithoutPEKPassword.getAndSet(notReady)) == false) {
                logger.warn(
                    "project encryption key not installed yet: nodes {} cannot persist it. Configure [{}] and the matching [{}<id>]"
                        + " secure setting on every master-eligible and data node and reload secure settings",
                    notReady,
                    ProjectEncryptionKeyPasswordSettings.ACTIVE_PASSWORD_ID_KEY,
                    ProjectEncryptionKeyPasswordSettings.PASSWORD_PREFIX
                );
            }
            if (response.hasFailures()) {
                logger.debug(
                    "project encryption key not installed yet: nodes did not report whether they can persist it {}",
                    response.failures()
                );
            }
            retryInstallLater();
        }, e -> {
            logger.warn("failed to check whether every node can persist the project encryption key", e);
            retryInstallLater();
        });
        // forked to avoid calling on the cluster applier thread
        threadPool.generic().execute(ActionRunnable.wrap(listener, l -> {
            try (var ignored = threadPool.getThreadContext().newEmptySystemContext()) {
                client.execute(TransportCanPersistKeyAction.TYPE, new TransportCanPersistKeyAction.Request(nodes), l);
            }
        }));
    }

    private void releaseInstall() {
        installInFlight.set(false);
        installRecheck.set(false);
    }

    private void submitInstall(String passwordId, Set<String> readyNodeIds) {
        try {
            byte[] plaintextPek = randomKey();
            String keyId = ProjectEncryptionKeyMetadata.generateKeyId();
            logger.debug("submitting install-project-encryption-key task: keyId={}, passwordId={}", keyId, passwordId);
            submitTaskIfOpen(
                "install-project-encryption-key",
                new InstallKeyTask(keyId, plaintextPek, passwordId, threadPool.absoluteTimeInMillis(), readyNodeIds)
            );
        } finally {
            installInFlight.set(false);
        }
        if (installRecheck.getAndSet(false)) {
            recheckIfMaster();
        }
    }

    /**
     * Releases the install and checks again after {@link #INSTALL_RETRY_INTERVAL}. Nodes don't tell the master when they reload secure
     * settings, so it has to ask again. A secure settings reload on this node, or a node that persists cluster state joining or leaving,
     * retries earlier.
     */
    private void retryInstallLater() {
        Object retry = new Object();
        pendingInstallRetry.set(retry);
        try {
            threadPool.schedule(() -> retryInstall(retry), INSTALL_RETRY_INTERVAL, threadPool.generic());
        } catch (Exception e) {
            pendingInstallRetry.set(null);
            releaseInstall();
            logger.debug("could not schedule a project encryption key install retry", e);
        }
    }

    private void retryInstall(Object retry) {
        if (pendingInstallRetry.compareAndSet(retry, null)) {
            releaseInstall();
            recheckIfMaster();
        }
    }

    private void recheckIfMaster() {
        if (closed == false) {
            ClusterState state = clusterService.state();
            if (state.nodes().isLocalNodeElectedMaster()
                && state.blocks().hasGlobalBlock(GatewayService.STATE_NOT_RECOVERED_BLOCK) == false) {
                checkPasswordId(state);
            }
        }
    }

    /** Restores the key from this node's own copy on disk, which it may be able to read once it has the password it is wrapped with. */
    private void scheduleRestore(ProjectEncryptionKeyMetadata degraded) {
        Settings settings = settingsSupplier.get();
        if (settings == lastRestoreAttempt.getAndSet(settings)) {
            return;
        }
        String activeKeyId = degraded.getActiveKeyId();
        if (ProjectEncryptionKeyPasswordSettings.hasActivePassword(settings) == false) {
            logger.warn(
                "the elected master holds no project encryption key [{}] and cannot persist it, so cluster state encryption is unavailable."
                    + " Configure [{}] and the matching [{}<id>] secure setting on this node and reload secure settings",
                activeKeyId,
                ProjectEncryptionKeyPasswordSettings.ACTIVE_PASSWORD_ID_KEY,
                ProjectEncryptionKeyPasswordSettings.PASSWORD_PREFIX
            );
            return;
        }
        threadPool.generic().execute(new AbstractRunnable() {
            @Override
            protected void doRun() {
                ProjectEncryptionKeyMetadata keys = ProjectEncryptionKeyMetadata.unwrapGatewayKeys(activeKeyId, pekEncryption);
                if (keys == null) {
                    onFailure(new IllegalStateException("this node has no copy of it on disk"));
                    return;
                }
                logger.info("restoring project encryption key [{}] from this node's disk", activeKeyId);
                submitTaskIfOpen("restore-project-encryption-keys", new RestoreKeysTask(keys));
            }

            @Override
            public void onFailure(Exception e) {
                logger.warn(
                    () -> Strings.format(
                        "the elected master holds no project encryption key [%s] and cannot read it from its disk, so cluster state"
                            + " encryption is unavailable. Configure the password the key on its disk is wrapped with and reload secure"
                            + " settings, or restart the master-eligible nodes so that a node that can read its copy is elected. If no"
                            + " node can, call POST /_encryption/_reset?accept_data_loss=true, which deletes all encrypted data",
                        activeKeyId
                    ),
                    e
                );
            }
        });
    }

    private void submitBeginRotation() {
        if (beginRotationInFlight.compareAndSet(false, true) == false) {
            return;
        }
        // Guard: abort rotation when no active password is configured; nodes must be able to persist the new key to disk.
        try {
            pekEncryption.activePasswordId();
        } catch (Exception e) {
            beginRotationInFlight.set(false);
            logger.warn("project encryption key rotation skipped: no active password configured", e);
            return;
        }
        byte[] plaintextPek = randomKey();
        String newKeyId = ProjectEncryptionKeyMetadata.generateKeyId();
        var task = new BeginRotationTask(newKeyId, plaintextPek, threadPool.absoluteTimeInMillis(), beginRotationInFlight);
        if (submitTaskIfOpen("begin-project-encryption-key-rotation", task) == false) {
            beginRotationInFlight.set(false);
        }
    }

    private void schedulePasswordIdChange(ProjectEncryptionKeyMetadata metadata, String newPasswordId) {
        if (passwordIdRotateInFlight.compareAndSet(false, true) == false) {
            return;
        }
        threadPool.generic().execute(new AbstractRunnable() {
            @Override
            public void doRun() {
                submitPasswordIdChange(metadata, newPasswordId);
            }

            @Override
            public void onAfter() {
                passwordIdRotateInFlight.set(false);
            }

            @Override
            public void onFailure(Exception e) {
                logger.warn(() -> "failed to submit password id change [" + metadata.getPasswordId() + " -> " + newPasswordId + "]", e);
            }
        });
    }

    private void submitPasswordIdChange(ProjectEncryptionKeyMetadata metadata, String newPasswordId) {
        String oldPasswordId = metadata.getPasswordId();
        Settings settings = this.settingsSupplier.get();
        if (ProjectEncryptionKeyPasswordSettings.hasPassword(settings, oldPasswordId) == false) {
            logger.warn(
                "password id update aborted: previous password [{}{}] is not configured",
                ProjectEncryptionKeyPasswordSettings.PASSWORD_PREFIX,
                oldPasswordId
            );
            return;
        }
        if (ProjectEncryptionKeyPasswordSettings.hasPassword(settings, newPasswordId) == false) {
            logger.warn(
                "password id update aborted: new password [{}{}] is not configured",
                ProjectEncryptionKeyPasswordSettings.PASSWORD_PREFIX,
                newPasswordId
            );
            return;
        }
        logger.info("submitting password id change: [{}] -> [{}]", oldPasswordId, newPasswordId);
        submitTaskIfOpen("update-project-encryption-key-password-id", new UpdatePasswordIdTask(newPasswordId, oldPasswordId));
    }

    private static byte[] randomKey() {
        byte[] keyBytes = new byte[PasswordBasedEncryption.PEK_LENGTH_BYTES];
        new SecureRandom().nextBytes(keyBytes);
        return keyBytes;
    }

    sealed interface KeyRotationTask extends ClusterStateTaskListener permits InstallKeyTask, BeginRotationTask, RetireKeysTask,
        ReEncryptApplyTask, UpdatePasswordIdTask, RestoreKeysTask {

        String description();

        @Override
        default void onFailure(@Nullable Exception e) {
            logger.log(MasterService.isPublishFailureException(e) ? Level.DEBUG : Level.WARN, () -> "failure during " + description(), e);
        }
    }

    /**
     * Installs the first key, but only if every node that persists cluster state is among {@code readyNodeIds}, the nodes that reported
     * they can persist the key.
     */
    record InstallKeyTask(String keyId, byte[] pekBytes, String passwordId, long generatedAt, Set<String> readyNodeIds)
        implements
            KeyRotationTask {
        @Override
        public String description() {
            return "project encryption key initial install";
        }

        @Override
        public String toString() {
            return "InstallKeyTask[keyId=" + keyId + ", passwordId=" + passwordId + ", generatedAt=" + generatedAt + "]";
        }
    }

    /** Replaces the key-less metadata an elected master published with the keys it read from its own disk for the same active key. */
    record RestoreKeysTask(ProjectEncryptionKeyMetadata keys) implements KeyRotationTask {
        @Override
        public String description() {
            return "project encryption key restore [" + keys.getActiveKeyId() + "]";
        }
    }

    record BeginRotationTask(String newKeyId, byte[] pekBytes, long generatedAt, AtomicBoolean inFlight) implements KeyRotationTask {
        @Override
        public String description() {
            return "project encryption key rotation begin";
        }

        @Override
        public void onFailure(@Nullable Exception e) {
            inFlight.set(false);
            KeyRotationTask.super.onFailure(e);
        }

        @Override
        public String toString() {
            return "BeginRotationTask[newKeyId=" + newKeyId + ", generatedAt=" + generatedAt + "]";
        }
    }

    record RetireKeysTask(long cutoffDeactivationMillis, String expectedActiveKeyId) implements KeyRotationTask {
        @Override
        public String description() {
            return "project encryption key retire (cutoff="
                + cutoffDeactivationMillis
                + ", expectedActiveKeyId="
                + expectedActiveKeyId
                + ")";
        }
    }

    record UpdatePasswordIdTask(String newPasswordId, String expectedOldPasswordId) implements KeyRotationTask {
        @Override
        public String description() {
            return "project encryption key password id update [" + expectedOldPasswordId + " -> " + newPasswordId + "]";
        }
    }

    record ReEncryptApplyTask(
        String customName,
        Metadata.ProjectCustom expectedOld,
        @Nullable Metadata.ProjectCustom newCustom,
        String expectedActiveKeyId,
        ActionListener<Void> completionListener
    ) implements KeyRotationTask {
        @Override
        public String description() {
            return "project encryption key re-encrypt [" + customName + "]";
        }

        @Override
        public void onFailure(Exception e) {
            logger.log(MasterService.isPublishFailureException(e) ? Level.DEBUG : Level.WARN, () -> "failure during " + description(), e);
            completionListener.onFailure(e);
        }
    }

    static class KeyRotationExecutor extends SimpleBatchedExecutor<KeyRotationTask, Void> {

        private final ProjectResolver projectResolver;
        private final ProjectEncryptionKeyMetadata.PekEncryption pekEncryption;
        private final boolean stateless;

        KeyRotationExecutor(ProjectResolver projectResolver, ProjectEncryptionKeyMetadata.PekEncryption pekEncryption, boolean stateless) {
            this.projectResolver = projectResolver;
            this.pekEncryption = pekEncryption;
            this.stateless = stateless;
        }

        @Override
        public Tuple<ClusterState, Void> executeTask(KeyRotationTask task, ClusterState clusterState) {
            ProjectState projectState = projectResolver.getProjectState(clusterState);
            ProjectEncryptionKeyMetadata existing = projectState.metadata().custom(ProjectEncryptionKeyMetadata.TYPE);
            // key-less metadata would turn into metadata that holds only a new key, losing the keys other nodes still hold
            if (existing != null && existing.isUnwrapFailed() && task instanceof RestoreKeysTask == false) {
                logger.debug("dropping [{}]: the elected master holds no project encryption key", task.description());
                return Tuple.tuple(clusterState, null);
            }

            return switch (task) {
                case InstallKeyTask install -> executeInstallInitial(clusterState, projectState, existing, install);
                case RestoreKeysTask restore -> executeRestoreKeys(clusterState, projectState, existing, restore);
                case BeginRotationTask begin -> executeBeginRotation(clusterState, projectState, existing, begin);
                case RetireKeysTask retireKeysTask -> executeRetireKeys(clusterState, projectState, existing, retireKeysTask);
                case UpdatePasswordIdTask updatePasswordId -> executeUpdatePasswordId(
                    clusterState,
                    projectState,
                    existing,
                    updatePasswordId
                );
                case ReEncryptApplyTask reEncryptTask -> executeReEncryptApply(clusterState, projectState, existing, reEncryptTask);
            };
        }

        private Tuple<ClusterState, Void> executeInstallInitial(
            ClusterState clusterState,
            ProjectState projectState,
            ProjectEncryptionKeyMetadata existing,
            InstallKeyTask task
        ) {
            if (existing != null) {
                return Tuple.tuple(clusterState, null);
            }
            if (clusterState.nodes()
                .getAllNodes()
                .stream()
                .anyMatch(
                    node -> PasswordPekEncryption.persistsClusterState(node.getRoles(), stateless)
                        && task.readyNodeIds().contains(node.getId()) == false
                )) {
                logger.debug("dropping project encryption key install: a node joined since the readiness check");
                return Tuple.tuple(clusterState, null);
            }
            ProjectEncryptionKeyMetadata metadata = new ProjectEncryptionKeyMetadata(
                Map.of(task.keyId(), new ProjectEncryptionKeyMetadata.KeyEntry(task.pekBytes(), task.generatedAt())),
                task.keyId(),
                task.passwordId(),
                Map.of(),
                pekEncryption
            );
            logger.info("installing project encryption key [{}] under password id [{}]", task.keyId(), task.passwordId());
            return Tuple.tuple(putMetadata(clusterState, projectState, metadata), null);
        }

        private Tuple<ClusterState, Void> executeRestoreKeys(
            ClusterState clusterState,
            ProjectState projectState,
            ProjectEncryptionKeyMetadata existing,
            RestoreKeysTask task
        ) {
            // never undo a reset or replace a newer key: only replace key-less metadata for the same active key
            if (existing == null
                || existing.isUnwrapFailed() == false
                || task.keys().getActiveKeyId().equals(existing.getActiveKeyId()) == false) {
                logger.debug("dropping restore task: project encryption key metadata changed to [{}]", existing);
                return Tuple.tuple(clusterState, null);
            }
            logger.info("restored project encryption key [{}]", task.keys().getActiveKeyId());
            return Tuple.tuple(putMetadata(clusterState, projectState, task.keys()), null);
        }

        private Tuple<ClusterState, Void> executeBeginRotation(
            ClusterState clusterState,
            ProjectState projectState,
            ProjectEncryptionKeyMetadata existing,
            BeginRotationTask task
        ) {
            if (existing == null) {
                logger.warn("ignoring begin-rotation task because no project encryption key is installed");
                return Tuple.tuple(clusterState, null);
            }
            Map<String, ProjectEncryptionKeyMetadata.KeyEntry> newEntries = new HashMap<>(existing.getKeys());
            newEntries.put(task.newKeyId(), new ProjectEncryptionKeyMetadata.KeyEntry(task.pekBytes(), task.generatedAt()));
            ProjectEncryptionKeyMetadata metadata = new ProjectEncryptionKeyMetadata(
                newEntries,
                task.newKeyId(),
                existing.getPasswordId(),
                existing.getHandlerKeyIds(),
                pekEncryption
            );
            logger.info("beginning project encryption key rotation: new active key [{}]", task.newKeyId());
            return Tuple.tuple(putMetadata(clusterState, projectState, metadata), null);
        }

        private Tuple<ClusterState, Void> executeRetireKeys(
            ClusterState clusterState,
            ProjectState projectState,
            ProjectEncryptionKeyMetadata existing,
            RetireKeysTask task
        ) {
            if (existing == null) {
                return Tuple.tuple(clusterState, null);
            }
            // a rotation since the tick makes handlers pending again; retiring now would skip their pass over the new active key
            if (existing.getActiveKeyId().equals(task.expectedActiveKeyId()) == false) {
                logger.debug(
                    "dropping retire task: activeKeyId drifted from [{}] to [{}]",
                    task.expectedActiveKeyId(),
                    existing.getActiveKeyId()
                );
                return Tuple.tuple(clusterState, null);
            }
            Set<String> retiredIds = existing.findRetireableKeyIds(task.cutoffDeactivationMillis());
            if (retiredIds.isEmpty()) {
                return Tuple.tuple(clusterState, null);
            }
            String activeKeyId = existing.getActiveKeyId();
            Map<String, ProjectEncryptionKeyMetadata.KeyEntry> retained = new HashMap<>(existing.getKeys());
            retained.keySet().removeAll(retiredIds);
            ProjectEncryptionKeyMetadata metadata = new ProjectEncryptionKeyMetadata(
                retained,
                activeKeyId,
                existing.getPasswordId(),
                existing.getHandlerKeyIds(),
                pekEncryption
            );
            logger.info("project encryption key retire: retained active key [{}], retired keys {}", activeKeyId, new TreeSet<>(retiredIds));
            return Tuple.tuple(putMetadata(clusterState, projectState, metadata), null);
        }

        private Tuple<ClusterState, Void> executeUpdatePasswordId(
            ClusterState clusterState,
            ProjectState projectState,
            ProjectEncryptionKeyMetadata existing,
            UpdatePasswordIdTask task
        ) {
            if (existing == null) {
                logger.debug("dropping password id update task: metadata removed");
                return Tuple.tuple(clusterState, null);
            }
            if (task.newPasswordId().equals(existing.getPasswordId())) {
                return Tuple.tuple(clusterState, null);
            }
            if (existing.getPasswordId().equals(task.expectedOldPasswordId()) == false) {
                logger.debug(
                    "dropping password id update: persisted passwordId [{}] no longer matches expected [{}]",
                    existing.getPasswordId(),
                    task.expectedOldPasswordId()
                );
                return Tuple.tuple(clusterState, null);
            }
            ProjectEncryptionKeyMetadata updated = new ProjectEncryptionKeyMetadata(
                existing.getKeys(),
                existing.getActiveKeyId(),
                task.newPasswordId(),
                existing.getHandlerKeyIds(),
                pekEncryption
            );
            return Tuple.tuple(putMetadata(clusterState, projectState, updated), null);
        }

        private Tuple<ClusterState, Void> executeReEncryptApply(
            ClusterState clusterState,
            ProjectState projectState,
            ProjectEncryptionKeyMetadata existing,
            ReEncryptApplyTask task
        ) {
            if (existing == null) {
                logger.debug("dropping re-encrypt task for [{}]: no PEK metadata installed", task.customName());
                return Tuple.tuple(clusterState, null);
            }
            if (existing.getActiveKeyId().equals(task.expectedActiveKeyId()) == false) {
                logger.debug(
                    "dropping re-encrypt task for [{}]: activeKeyId drifted from [{}] to [{}]",
                    task.customName(),
                    task.expectedActiveKeyId(),
                    existing.getActiveKeyId()
                );
                return Tuple.tuple(clusterState, null);
            }
            Metadata.ProjectCustom current = projectState.metadata().custom(task.customName());
            if (current != task.expectedOld()) {
                logger.debug("dropping re-encrypt task for [{}]: slice mutated between compute and apply", task.customName());
                return Tuple.tuple(clusterState, null);
            }
            ProjectEncryptionKeyMetadata updatedPek = existing.withHandlerKeyId(task.customName(), task.expectedActiveKeyId());
            ClusterState newState = clusterState.copyAndUpdateProject(projectState.projectId(), b -> {
                if (task.newCustom() != null) {
                    b = b.putCustom(task.customName(), task.newCustom());
                }
                b.putCustom(ProjectEncryptionKeyMetadata.TYPE, updatedPek);
            });
            return Tuple.tuple(newState, null);
        }

        private static ClusterState putMetadata(
            ClusterState clusterState,
            ProjectState projectState,
            ProjectEncryptionKeyMetadata metadata
        ) {
            return clusterState.copyAndUpdateProject(
                projectState.projectId(),
                b -> b.putCustom(ProjectEncryptionKeyMetadata.TYPE, metadata)
            );
        }

        @Override
        public void taskSucceeded(KeyRotationTask task, Void unused) {
            logger.debug("[{}] succeeded", task.description());
            if (task instanceof ReEncryptApplyTask reEncrypt) {
                reEncrypt.completionListener().onResponse(null);
            }
            if (task instanceof BeginRotationTask begin) {
                begin.inFlight().set(false);
            }
        }

        @Override
        public String describeTasks(List<KeyRotationTask> tasks) {
            Map<String, Long> byType = tasks.stream().collect(Collectors.groupingBy(KeyRotationTask::description, Collectors.counting()));
            return "project encryption key tasks " + byType + " [" + tasks.size() + " pending]";
        }
    }
}
