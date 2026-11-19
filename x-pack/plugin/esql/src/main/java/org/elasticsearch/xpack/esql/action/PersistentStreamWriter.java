/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.esql.action;

import org.elasticsearch.common.UUIDs;
import org.elasticsearch.compute.data.Page;
import org.elasticsearch.core.Nullable;
import org.elasticsearch.tasks.TaskId;
import org.elasticsearch.xpack.core.esql.action.ColumnInfo;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public interface PersistentStreamWriter {

    PersistentStreamWriter NOOP = new PersistentStreamWriter() {
        @Override
        public String createStarted(
            TaskId taskId,
            @Nullable Instant expiration,
            List<ColumnInfo> columns,
            Map<String, String> headers,
            List<String> warnings
        ) {
            return UUIDs.randomBase64UUID();
        }

        @Override
        public void appendPage(int seq, Page page, Runnable onCapacity) {
            onCapacity.run();
        }

        @Override
        public void markComplete(boolean partial, long tookMillis, long pages, long rows) {}

        @Override
        public void markFailed(boolean partial, long tookMillis, Exception e) {}

        @Override
        public void markCanceled() {}
    };

    String createStarted(
        TaskId taskId,
        @Nullable Instant expiration,
        List<ColumnInfo> columns,
        Map<String, String> headers,
        List<String> warnings
    );

    void appendPage(int seq, Page page, Runnable onCapacity);

    void markComplete(boolean partial, long tookMillis, long pages, long rows);

    void markFailed(boolean partial, long tookMillis, Exception e);

    void markCanceled();
}
