/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.encryption;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.cluster.node.DiscoveryNodeRole;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.core.Nullable;
import org.elasticsearch.xpack.encryption.spi.EncryptedData;

import java.util.Set;
import java.util.function.Supplier;

/**
 * Password-based {@link ProjectEncryptionKeyMetadata.PekEncryption} implementation. Wraps and unwraps PEK bytes for disk (GATEWAY)
 * serialization using PBKDF2-derived AES-256-GCM (see {@link PasswordBasedEncryption}).
 *
 * <p>The active password id and password material are sourced from a {@link Supplier} so that secure-settings reloads are reflected
 * automatically: the supplier is re-evaluated on every call.
 */
public final class PasswordPekEncryption implements ProjectEncryptionKeyMetadata.PekEncryption {

    private final Supplier<Settings> settingsSupplier;
    private final ProjectEncryptionKeyMetadata.GatewayKeys gatewayKeys = new ProjectEncryptionKeyMetadata.GatewayKeys();

    private record WrapCheck(Settings settings, @Nullable String failure) {}

    private volatile WrapCheck wrapCheck;

    PasswordPekEncryption(Supplier<Settings> settingsSupplier) {
        this.settingsSupplier = settingsSupplier;
    }

    @Override
    public ProjectEncryptionKeyMetadata.GatewayKeys gatewayKeys() {
        return gatewayKeys;
    }

    /**
     * Returns whether a node with {@code roles} persists cluster state, and so must be able to wrap the key. Mirrors
     * {@link org.elasticsearch.gateway.GatewayMetaState}, which gives master-eligible and data nodes an on-disk persisted state. On
     * stateless only master-eligible nodes persist it, to the object store when elected, and they wrap the key with their own password.
     */
    static boolean persistsClusterState(Set<DiscoveryNodeRole> roles, boolean stateless) {
        return roles.contains(DiscoveryNodeRole.MASTER_ROLE)
            || (stateless == false && roles.stream().anyMatch(DiscoveryNodeRole::canContainData));
    }

    /** Returns whether this node can write the key to its disk. */
    boolean canWrapForDisk() {
        return wrapForDiskFailure() == null;
    }

    /** Returns why this node cannot write the key to its disk, or {@code null} if it can. Cached per secure settings snapshot. */
    @Nullable
    String wrapForDiskFailure() {
        Settings settings = settingsSupplier.get();
        WrapCheck check = wrapCheck;
        if (check == null || check.settings() != settings) {
            check = new WrapCheck(settings, ProjectEncryptionKeyPasswordSettings.wrapForDiskFailure(settings));
            wrapCheck = check;
        }
        return check.failure();
    }

    /** Returns whether this node has the password its on-disk copy of the key is wrapped with, so it can read the copy. */
    boolean canReadKeyOnDisk() {
        String passwordId = gatewayKeys.passwordId();
        return passwordId != null && ProjectEncryptionKeyPasswordSettings.hasPassword(settingsSupplier.get(), passwordId);
    }

    @Override
    public String activePasswordId() {
        String id = ProjectEncryptionKeyPasswordSettings.getActivePasswordId(settingsSupplier.get());
        if (id == null) {
            throw new ElasticsearchException(
                "cannot wrap PEK for disk: [" + ProjectEncryptionKeyPasswordSettings.ACTIVE_PASSWORD_ID_KEY + "] is not configured"
            );
        }
        return id;
    }

    @Override
    public WrappedKey wrap(byte[] plaintextPek) {
        Settings s = settingsSupplier.get();
        String passwordId = ProjectEncryptionKeyPasswordSettings.getActivePasswordId(s);
        if (passwordId == null) {
            throw new ElasticsearchException(
                "cannot wrap PEK for disk: [" + ProjectEncryptionKeyPasswordSettings.ACTIVE_PASSWORD_ID_KEY + "] is not configured"
            );
        }
        try (SecureString password = ProjectEncryptionKeyPasswordSettings.getPassword(s, passwordId)) {
            if (password == null) {
                throw new ElasticsearchException(
                    "cannot wrap PEK for disk: secure setting ["
                        + ProjectEncryptionKeyPasswordSettings.PASSWORD_PREFIX
                        + passwordId
                        + "] is not configured"
                );
            }
            return new WrappedKey(passwordId, PasswordBasedEncryption.wrap(plaintextPek, passwordId, password.getChars()).payload());
        }
    }

    @Override
    public byte[] unwrap(byte[] wrappedPek, String passwordId) {
        try (SecureString password = ProjectEncryptionKeyPasswordSettings.getPassword(settingsSupplier.get(), passwordId)) {
            if (password == null) {
                throw new ElasticsearchException(
                    "cannot unwrap PEK from disk: secure setting ["
                        + ProjectEncryptionKeyPasswordSettings.PASSWORD_PREFIX
                        + passwordId
                        + "] is not configured"
                );
            }
            return PasswordBasedEncryption.unwrap(new EncryptedData(passwordId, wrappedPek), password.getChars());
        }
    }
}
