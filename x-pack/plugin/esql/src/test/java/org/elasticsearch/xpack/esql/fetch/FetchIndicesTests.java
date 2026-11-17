/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.esql.fetch;

import org.elasticsearch.cluster.metadata.AliasMetadata;
import org.elasticsearch.cluster.metadata.DataStream;
import org.elasticsearch.cluster.metadata.DataStreamTestHelper;
import org.elasticsearch.cluster.metadata.IndexMetadata;
import org.elasticsearch.cluster.metadata.ProjectId;
import org.elasticsearch.cluster.metadata.ProjectMetadata;
import org.elasticsearch.index.IndexVersion;
import org.elasticsearch.index.shard.ShardId;
import org.elasticsearch.indices.TestIndexNameExpressionResolver;
import org.elasticsearch.search.internal.ShardSearchContextId;
import org.elasticsearch.test.ESTestCase;

import java.util.ArrayList;
import java.util.List;

import static org.hamcrest.Matchers.arrayContaining;
import static org.hamcrest.Matchers.containsString;

/**
 * The names a fetch request carries, which security authorizes the request with. They never hold a wildcard, which
 * security refuses in such a request, and they name each index of the request the way the query reached it.
 */
public class FetchIndicesTests extends ESTestCase {
    private static final String BACKING_INDEX = DataStream.getDefaultBackingIndexName("metrics-app", 1);
    private static final IndexMetadata BACKING_INDEX_METADATA = index(BACKING_INDEX).build();

    /**
     * {@code logs-1} and {@code logs-2} behind the alias {@code logs}, {@code other} without one, and the data stream
     * {@code metrics-app}.
     */
    private static final ProjectMetadata PROJECT = ProjectMetadata.builder(ProjectId.DEFAULT)
        .put(index("logs-1").putAlias(AliasMetadata.builder("logs")))
        .put(index("logs-2").putAlias(AliasMetadata.builder("logs")))
        .put(index("other"))
        .put(BACKING_INDEX_METADATA, false)
        .put(DataStreamTestHelper.newInstance("metrics-app", List.of(BACKING_INDEX_METADATA.getIndex())))
        .build();

    public void testNamesAnIndexTheQueryNamed() {
        assertThat(namesOf(List.of("other"), "other"), arrayContaining("other"));
    }

    /**
     * A wildcard matches the indices themselves, so the request names each of its indices instead of the wildcard.
     */
    public void testNamesTheIndicesAWildcardMatched() {
        assertThat(namesOf(List.of("logs-*", "oth*"), "logs-2", "other", "logs-2"), arrayContaining("logs-2", "other"));
    }

    /**
     * A user may read an index only through an alias, so an index the query reached through an alias is named by it.
     */
    public void testNamesTheAliasTheQueryReachedAnIndexThrough() {
        assertThat(namesOf(List.of("logs"), "logs-1", "logs-2"), arrayContaining("logs"));
    }

    public void testNamesTheIndexAndTheAliasWhenTheQueryNamedBoth() {
        assertThat(namesOf(List.of("logs-1", "logs"), "logs-1"), arrayContaining("logs-1", "logs"));
    }

    /**
     * The backing index of a data stream the query named, which security grants through the data stream.
     */
    public void testNamesTheBackingIndexOfADataStream() {
        assertThat(namesOf(List.of("metrics-*"), BACKING_INDEX), arrayContaining(BACKING_INDEX));
    }

    /**
     * Without expressions, a resolution would cover every index.
     */
    public void testNeedsTheIndexExpressionsOfTheRelation() {
        IllegalArgumentException e = expectThrows(
            IllegalArgumentException.class,
            () -> FetchIndices.resolve(TestIndexNameExpressionResolver.newInstance(), PROJECT, List.of())
        );
        assertThat(e.getMessage(), containsString("index expressions"));
    }

    private static String[] namesOf(List<String> expressions, String... shardIndices) {
        FetchIndices indices = FetchIndices.resolve(TestIndexNameExpressionResolver.newInstance(), PROJECT, expressions);
        List<FetchRequest.ShardDocs> shards = new ArrayList<>();
        for (int s = 0; s < shardIndices.length; s++) {
            shards.add(
                new FetchRequest.ShardDocs(
                    new ShardId(shardIndices[s], "uuid", s),
                    new ShardSearchContextId("session", s),
                    false,
                    new int[] { 0 },
                    new int[] { 0 }
                )
            );
        }
        return indices.namesOf(shards);
    }

    private static IndexMetadata.Builder index(String name) {
        return IndexMetadata.builder(name).settings(indexSettings(IndexVersion.current(), 1, 0));
    }
}
