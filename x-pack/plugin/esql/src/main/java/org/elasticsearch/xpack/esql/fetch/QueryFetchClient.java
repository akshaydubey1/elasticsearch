/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.esql.fetch;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.OriginalIndices;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.compute.operator.DriverCompletionInfo;
import org.elasticsearch.search.internal.ShardSearchContextId;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.transport.RemoteClusterAware;
import org.elasticsearch.xpack.esql.core.expression.Attribute;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Sends the fetch requests of one {@link org.elasticsearch.xpack.esql.plan.physical.FetchExec} from the coordinator of its
 * query to the nodes of its cluster.
 * <p>
 * Each request is a child of the query's task, so cancelling the query cancels it. It names the indices of its shards, or
 * the aliases the query reached them through ({@link FetchIndices}), so security authorizes it for every shard it reads.
 * The drivers that load the documents count as drivers of the query: their counters and profiles go to the query's compute
 * listener, once per request, whether it succeeds or not. Otherwise the query would wait for them forever.
 */
final class QueryFetchClient implements FetchOperator.Client {
    /**
     * Sends one fetch request. {@link FetchService#sendFetch} outside of tests.
     */
    @FunctionalInterface
    interface Sender {
        void send(DiscoveryNode target, FetchRequest request, Task parentTask, ActionListener<FetchResponse> listener);
    }

    private final Sender sender;
    private final ThreadContext threadContext;
    private final FetchNodeDirectory nodes;
    private final QueryFetchScope scope;
    private final FetchIndices indices;

    /**
     * @param indices the names of the indices of the relation the documents come from
     */
    QueryFetchClient(Sender sender, ThreadContext threadContext, FetchNodeDirectory nodes, QueryFetchScope scope, FetchIndices indices) {
        this.sender = sender;
        this.threadContext = threadContext;
        this.nodes = nodes;
        this.scope = scope;
        this.indices = indices;
    }

    @Override
    public ThreadContext threadContext() {
        return threadContext;
    }

    @Override
    public void node(FetchNode node, ActionListener<DiscoveryNode> listener) {
        nodes.find(node, listener);
    }

    @Override
    public void fetch(
        DiscoveryNode node,
        String clusterAlias,
        List<FetchRequest.ShardDocs> shards,
        List<Attribute> attributes,
        ActionListener<FetchResponse> listener
    ) {
        if (RemoteClusterAware.LOCAL_CLUSTER_GROUP_KEY.equals(clusterAlias) == false) {
            // the directory refuses the nodes of remote clusters before any fetch goes out
            throw new IllegalStateException("the fetch phase reads the local cluster only, not [" + clusterAlias + "]");
        }
        FetchRequest request = new FetchRequest(
            scope.sessionId(),
            clusterAlias,
            new OriginalIndices(indices.namesOf(shards), SearchRequest.DEFAULT_INDICES_OPTIONS),
            shards,
            scope.configuration(),
            attributes
        );
        FetchNode fetchNode = new FetchNode(clusterAlias, node.getId());
        ActionListener<DriverCompletionInfo> drivers = scope.completionInfo().get();
        ActionListener<FetchResponse> countingDrivers = ActionListener.notifyOnce(new ActionListener<>() {
            @Override
            public void onResponse(FetchResponse response) {
                try {
                    scope.fetchContexts().freedByTheirNode(fetchNode, freedByTheNode(shards));
                    listener.onResponse(response);
                } finally {
                    drivers.onResponse(response.completionInfo());
                }
            }

            @Override
            public void onFailure(Exception e) {
                try {
                    listener.onFailure(e);
                } finally {
                    // the failure fails the query through the fetch operator, so the drivers complete without counters
                    drivers.onResponse(DriverCompletionInfo.EMPTY);
                }
            }
        });
        try {
            sender.send(node, request, scope.rootTask(), countingDrivers);
        } catch (Exception e) {
            countingDrivers.onFailure(e);
        }
    }

    /**
     * The contexts that the node freed once it answered: those the request read for the last time. A request that
     * answered opened all of its shards. The lease keeps the contexts of a request that failed, which may never have
     * reached the node, and frees them once the fetch ended.
     */
    private static List<ShardSearchContextId> freedByTheNode(List<FetchRequest.ShardDocs> shards) {
        List<ShardSearchContextId> freed = new ArrayList<>();
        for (FetchRequest.ShardDocs shard : shards) {
            if (shard.freeAfterFetch()) {
                freed.add(shard.contextId());
            }
        }
        return freed;
    }

    @Override
    public void cutEnded(Set<ShardSearchContextId> read) {
        scope.fetchContexts().cutEnded(read);
    }

    @Override
    public void fetchEnded() {
        scope.fetchContexts().fetchEnded();
    }
}
