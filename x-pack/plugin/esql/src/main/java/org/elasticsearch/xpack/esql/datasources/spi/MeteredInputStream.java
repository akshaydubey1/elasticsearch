/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.esql.datasources.spi;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Counts physical bytes delivered to the caller by a leaf {@link StorageObject#newStream} into the
 * profile {@link StorageObjectMetricsCounters} and publishes those delivered bytes as one APM bytes
 * event at close or abort.
 * <p>
 * The tally is a plain {@code long} on the producer thread — no per-byte atomics. Live
 * {@code _tasks} snapshots may trail by one {@link #PUBLISH_CHUNK_BYTES} chunk; close/abort
 * flushes the remainder so the query profile is exact. Abort-in-flight slack (bytes sitting
 * in an SDK buffer that never reached {@code read}) is unobservable and excluded.
 * <p>
 * {@link #abort()} is {@link #close()}: the inner stream decides drain vs drop. S3 leftover drain
 * after a small-tail close is a second APM bytes event via
 * {@link StorageObjectMetricsCounters#publishDrainedBytes}.
 */
public final class MeteredInputStream extends FilterInputStream {

    /** How many newly received bytes accumulate before a live profile publish. */
    static final int PUBLISH_CHUNK_BYTES = 256 * 1024;

    private final StorageObjectMetricsCounters counters;
    private final AtomicBoolean closed = new AtomicBoolean();

    private long local;
    private long lastPublished;

    public MeteredInputStream(InputStream in, StorageObjectMetricsCounters counters) {
        super(in);
        this.counters = counters;
    }

    @Override
    public int read() throws IOException {
        int b = in.read();
        if (b >= 0) {
            account(1L);
        }
        return b;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        int n = in.read(b, off, len);
        if (n > 0) {
            account(n);
        }
        return n;
    }

    @Override
    public long skip(long n) throws IOException {
        long skipped = in.skip(n);
        if (skipped > 0) {
            account(skipped);
        }
        return skipped;
    }

    @Override
    public boolean markSupported() {
        return false;
    }

    @Override
    public void mark(int readlimit) {
        // Received-byte accounting cannot follow a reset; refuse mark so callers do not double-count.
    }

    @Override
    public void reset() throws IOException {
        throw new IOException("mark/reset not supported by MeteredInputStream");
    }

    /**
     * Same as {@link #close()}. Kept so existing abort call sites compile while the leaf owns
     * drain vs drop.
     */
    public void abort() throws IOException {
        close();
    }

    @Override
    public void close() throws IOException {
        finish();
    }

    private void account(long n) {
        local += n;
        long unpublished = local - lastPublished;
        if (unpublished >= PUBLISH_CHUNK_BYTES) {
            counters.addBytes(unpublished);
            lastPublished = local;
        }
    }

    private void finish() throws IOException {
        if (closed.compareAndSet(false, true) == false) {
            return;
        }
        long remainder = local - lastPublished;
        if (remainder > 0) {
            counters.addBytes(remainder);
            lastPublished = local;
        }
        counters.publishStreamBytes(local);
        in.close();
    }
}
