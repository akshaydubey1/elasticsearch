/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.encryption;

import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.core.Nullable;

/**
 * Test-only access to package-private project encryption key internals ({@link ProjectEncryptionKeyMetadata},
 * {@link ProjectEncryptionKeyPasswordSettings}) for integration tests that live outside this package.
 */
public final class EncryptionPasswordTestUtil {

    public static final String ACTIVE_PASSWORD_ID_KEY = ProjectEncryptionKeyPasswordSettings.ACTIVE_PASSWORD_ID_KEY;
    public static final String PASSWORD_KEY_PREFIX = ProjectEncryptionKeyPasswordSettings.PASSWORD_PREFIX;

    private EncryptionPasswordTestUtil() {}

    /** Whether the state holds a usable project encryption key, rather than none or one the node could not unwrap. */
    public static boolean hasUsableKey(ClusterState state) {
        ProjectEncryptionKeyMetadata metadata = metadata(state);
        return metadata != null && metadata.isUnwrapFailed() == false;
    }

    /** Whether the state holds a project encryption key that the node could not unwrap from its persisted cluster state. */
    public static boolean keyUnwrapFailed(ClusterState state) {
        ProjectEncryptionKeyMetadata metadata = metadata(state);
        return metadata != null && metadata.isUnwrapFailed();
    }

    /** The id of the password the project encryption key is wrapped with, or {@code null} if there is no key. */
    @Nullable
    public static String keyPasswordId(ClusterState state) {
        ProjectEncryptionKeyMetadata metadata = metadata(state);
        return metadata == null ? null : metadata.getPasswordId();
    }

    /** Whether the node's current secure settings let it wrap the project encryption key for persisting. */
    public static boolean canWrapForDisk(PasswordPekEncryption pekEncryption) {
        return pekEncryption.canWrapForDisk();
    }

    private static ProjectEncryptionKeyMetadata metadata(ClusterState state) {
        return state.metadata().getSingleProjectCustom(ProjectEncryptionKeyMetadata.TYPE);
    }
}
