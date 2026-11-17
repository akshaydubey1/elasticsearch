/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.esql.fetch;

import org.elasticsearch.cluster.metadata.IndexAbstraction;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver.ResolvedExpression;
import org.elasticsearch.cluster.metadata.ProjectMetadata;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The indices a fetch request names. Security refuses wildcards in a request that names its indices, like a fetch request,
 * so it names the index of each of its shards, or the aliases the query reached it through. Security then authorizes the
 * request for every shard it reads, like the shard requests of {@code _search}, which name their indices the same way
 * ({@code TransportSearchAction#buildPerIndexOriginalIndices}).
 */
final class FetchIndices {
    private final IndexNameExpressionResolver resolver;
    private final ProjectMetadata project;
    private final Set<ResolvedExpression> resolved;
    private final Set<String> resources;

    private FetchIndices(IndexNameExpressionResolver resolver, ProjectMetadata project, Set<ResolvedExpression> resolved) {
        this.resolver = resolver;
        this.project = project;
        this.resolved = resolved;
        this.resources = resolved.stream().map(ResolvedExpression::resource).collect(Collectors.toSet());
    }

    /**
     * @param expressions the index expressions the user wrote for the local cluster
     */
    static FetchIndices resolve(IndexNameExpressionResolver resolver, ProjectMetadata project, List<String> expressions) {
        if (expressions.isEmpty()) {
            // no expression would resolve to every index
            throw new IllegalArgumentException("a fetch needs the index expressions of its relation");
        }
        return new FetchIndices(resolver, project, resolver.resolveExpressionsIgnoringRemotes(project, expressions.toArray(String[]::new)));
    }

    /**
     * The names a request for {@code shards} carries, each name once.
     */
    String[] namesOf(List<FetchRequest.ShardDocs> shards) {
        Set<String> names = new LinkedHashSet<>();
        for (FetchRequest.ShardDocs shard : shards) {
            addNamesOf(shard.shardId().getIndexName(), names);
        }
        return names.toArray(String[]::new);
    }

    /**
     * The index itself when the expressions name it, match it with a wildcard or name its data stream, or when no alias
     * among them points to it. Its aliases among the expressions otherwise, or as well.
     */
    private void addNamesOf(String index, Set<String> names) {
        String[] aliases = resolver.allIndexAliases(project, index, resolved);
        if (aliases == null || aliases.length == 0 || resources.contains(index) || dataStreamIsNamed(index)) {
            names.add(index);
        }
        if (aliases != null) {
            names.addAll(List.of(aliases));
        }
    }

    private boolean dataStreamIsNamed(String index) {
        IndexAbstraction abstraction = project.getIndicesLookup().get(index);
        return abstraction != null
            && abstraction.getParentDataStream() != null
            && resources.contains(abstraction.getParentDataStream().getName());
    }
}
