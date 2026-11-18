/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.encryption;

import org.apache.logging.log4j.core.LogEvent;
import org.elasticsearch.core.Strings;
import org.elasticsearch.test.MockLog;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/** Helpers shared by the encryption integration tests here and in the stateless module. */
public final class EncryptionIntegTestUtils {

    private EncryptionIntegTestUtils() {}

    /** File settings whose cluster secrets hold the given secrets, as alternating names and values. */
    public static String clusterSecretsJson(long version, String... namesAndValues) {
        StringBuilder secrets = new StringBuilder();
        for (int i = 0; i < namesAndValues.length; i += 2) {
            secrets.append(i == 0 ? "" : ",")
                .append('"')
                .append(namesAndValues[i])
                .append("\":\"")
                .append(namesAndValues[i + 1])
                .append('"');
        }
        return Strings.format("""
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
    }

    /** The joining node rejects the cluster's join validation, and logs the reason the master sends back. */
    public static final class JoinRejectedExpectation implements MockLog.LoggingExpectation {
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
