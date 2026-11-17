/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.esql.fetch;

import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.action.support.PlainActionFuture;
import org.elasticsearch.client.internal.transport.NoNodeAvailableException;
import org.elasticsearch.cluster.metadata.IndexMetadata;
import org.elasticsearch.cluster.metadata.ProjectId;
import org.elasticsearch.cluster.metadata.ProjectMetadata;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.cluster.node.DiscoveryNodeUtils;
import org.elasticsearch.cluster.node.DiscoveryNodes;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.compute.operator.DriverCompletionInfo;
import org.elasticsearch.compute.test.ComputeTestCase;
import org.elasticsearch.core.TimeValue;
import org.elasticsearch.index.IndexVersion;
import org.elasticsearch.index.shard.ShardId;
import org.elasticsearch.indices.TestIndexNameExpressionResolver;
import org.elasticsearch.search.internal.ShardSearchContextId;
import org.elasticsearch.tasks.CancellableTask;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.tasks.TaskId;
import org.elasticsearch.xpack.esql.EsqlTestUtils;
import org.elasticsearch.xpack.esql.core.expression.Attribute;
import org.elasticsearch.xpack.esql.core.expression.ReferenceAttribute;
import org.elasticsearch.xpack.esql.core.tree.Source;
import org.elasticsearch.xpack.esql.core.type.DataType;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.sameInstance;

/**
 * One fetch request as the coordinator sends it: what it carries, and that the drivers of the fetch reach the query
 * exactly once, whatever happens to the request. A missed completion would hang the query, a second one would count the
 * drivers twice.
 */
public class QueryFetchClientTests extends ComputeTestCase {
    private static final DiscoveryNode NODE = DiscoveryNodeUtils.create("n1");
    /**
     * {@link #NODE}, as the lease names the node of its contexts.
     */
    private static final FetchNode FETCH_NODE = FetchNode.local("n1");
    private static final FetchRequest.ShardDocs SHARD = new FetchRequest.ShardDocs(
        new ShardId("logs-1", "uuid", 0),
        new ShardSearchContextId("session", 7),
        false,
        new int[] { 0, 0, 2 },
        new int[] { 3, 8, 1 }
    );
    private static final DriverCompletionInfo FETCH_DRIVERS = new DriverCompletionInfo(
        3,
        6,
        3,
        0,
        0,
        0,
        0,
        0,
        List.of(),
        List.of(),
        Map.of(),
        false,
        false,
        Set.of()
    );

    private final CancellableTask rootTask = new CancellableTask(
        1,
        "transport",
        "indices:data/read/esql",
        "",
        TaskId.EMPTY_TASK_ID,
        Map.of()
    );
    private final ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
    private final QueryDrivers drivers = new QueryDrivers();

    /**
     * The request is a child of the query's task, names the index of its shard without wildcards, and loads the attributes
     * of the fetch.
     */
    public void testSendsTheRequestAsAChildOfTheQuery() {
        List<Sent> sent = new ArrayList<>();
        List<Attribute> attributes = List.of(new ReferenceAttribute(Source.EMPTY, "message", DataType.KEYWORD));
        QueryFetchClient client = client((target, request, parentTask, listener) -> sent.add(new Sent(target, request, parentTask)));
        client.fetch(NODE, "", List.of(SHARD), attributes, ActionListener.noop());

        assertThat(client.threadContext(), sameInstance(threadContext));
        assertThat(sent.size(), equalTo(1));
        assertThat(sent.getFirst().target(), sameInstance(NODE));
        assertThat(sent.getFirst().parentTask(), sameInstance(rootTask));
        FetchRequest request = sent.getFirst().request();
        assertThat(request.sessionId(), equalTo("query-session"));
        assertThat(request.clusterAlias(), equalTo(""));
        assertThat(request.indices(), equalTo(new String[] { "logs-1" }));
        assertThat(request.indicesOptions(), equalTo(SearchRequest.DEFAULT_INDICES_OPTIONS));
        assertThat(request.shards(), equalTo(List.of(SHARD)));
        assertThat(request.attributes(), equalTo(attributes));
    }

    public void testAResponseCountsItsDrivers() {
        FetchResponse response = new FetchResponse(blockFactory(), List.of(), FETCH_DRIVERS, 0, 0);
        try {
            List<FetchResponse> received = new ArrayList<>();
            client((target, request, parentTask, listener) -> listener.onResponse(response)).fetch(
                NODE,
                "",
                List.of(SHARD),
                List.of(),
                ActionListener.assertOnce(ActionListener.wrap(received::add, e -> {
                    throw new AssertionError(e);
                }))
            );
            assertThat(received, contains(sameInstance(response)));
            assertThat(drivers.completed, contains(FETCH_DRIVERS));
        } finally {
            response.decRef();
        }
    }

    public void testAFailedRequestCompletesItsDrivers() {
        List<Exception> failures = new ArrayList<>();
        IllegalStateException rejected = new IllegalStateException("rejected");
        client((target, request, parentTask, listener) -> listener.onFailure(rejected)).fetch(
            NODE,
            "",
            List.of(SHARD),
            List.of(),
            ActionListener.assertOnce(ActionListener.wrap(r -> fail("unexpected response"), failures::add))
        );
        assertThat(failures, contains(sameInstance(rejected)));
        assertThat(drivers.completed, contains(DriverCompletionInfo.EMPTY));
    }

    /**
     * A request that fails before it leaves the node still completes its listener and its drivers.
     */
    public void testARequestThatCannotBeSentCompletesItsDrivers() {
        List<Exception> failures = new ArrayList<>();
        QueryFetchClient.Sender cannotSend = (target, request, parentTask, listener) -> { throw new IllegalStateException("not sent"); };
        client(cannotSend).fetch(
            NODE,
            "",
            List.of(SHARD),
            List.of(),
            ActionListener.assertOnce(ActionListener.wrap(r -> fail("unexpected response"), failures::add))
        );
        assertThat(failures.size(), equalTo(1));
        assertThat(failures.getFirst().getMessage(), equalTo("not sent"));
        assertThat(drivers.completed, contains(DriverCompletionInfo.EMPTY));
    }

    /**
     * When a listener throws, the transport completes it a second time, with the failure. The drivers count once.
     */
    public void testASecondCompletionIsIgnored() {
        FetchResponse response = new FetchResponse(blockFactory(), List.of(), FETCH_DRIVERS, 0, 0);
        try {
            List<Exception> failures = new ArrayList<>();
            client((target, request, parentTask, listener) -> {
                try {
                    listener.onResponse(response);
                } catch (Exception e) {
                    listener.onFailure(e);
                }
            }).fetch(NODE, "", List.of(SHARD), List.of(), new ActionListener<>() {
                @Override
                public void onResponse(FetchResponse fetchResponse) {
                    throw new IllegalStateException("can't read the response");
                }

                @Override
                public void onFailure(Exception e) {
                    failures.add(e);
                }
            });
            assertThat(failures, empty());
            assertThat(drivers.completed, contains(FETCH_DRIVERS));
        } finally {
            response.decRef();
        }
    }

    /**
     * The client finds the nodes through the directory of this node: a node of the local cluster from its cluster state.
     */
    public void testFindsTheNodesOfTheLocalCluster() {
        QueryFetchClient client = client((target, request, parentTask, listener) -> fail("nothing to send"));
        PlainActionFuture<DiscoveryNode> found = new PlainActionFuture<>();
        client.node(FETCH_NODE, found);
        assertThat(found.actionGet(), sameInstance(NODE));
        PlainActionFuture<DiscoveryNode> left = new PlainActionFuture<>();
        client.node(FetchNode.local("n2"), left);
        expectThrows(NoNodeAvailableException.class, left::actionGet);
    }

    /**
     * The ends of the cut and of the fetch reach the lease of the query, for the execution of the client: the end of the
     * cut frees the context no row read, and the end of the fetch the one they read.
     */
    public void testTheEndsOfTheCutAndTheFetchReachTheLeaseOfItsExecution() {
        RecordedLease recorded = leaseThatRecordsFrees();
        QueryFetchClient client = new QueryFetchClient(
            (target, request, parentTask, listener) -> fail("nothing to send"),
            threadContext,
            directory(),
            scope(recorded.execution()),
            indices()
        );
        ShardSearchContextId read = new ShardSearchContextId("session", 1);
        ShardSearchContextId unread = new ShardSearchContextId("session", 2);
        recorded.arrived(read, unread);

        client.cutEnded(Set.of(read));
        assertThat(recorded.transport().freed(), equalTo(Set.of(unread)));

        client.fetchEnded();
        assertThat(recorded.transport().freed(), equalTo(Set.of(unread, read)));
        recorded.lease().close();
    }

    /**
     * Once the response of the request that reads a context for the last time arrived, its node freed the context, so the
     * lease of the execution no longer frees it.
     */
    public void testTheLeaseLetsGoOfTheContextsTheNodeFreedAfterTheirLastFetch() {
        FetchResponse response = new FetchResponse(blockFactory(), List.of(), FETCH_DRIVERS, 0, 0);
        try {
            RecordedLease recorded = leaseThatRecordsFrees();
            QueryFetchClient client = new QueryFetchClient(
                (target, request, parentTask, listener) -> listener.onResponse(response),
                threadContext,
                directory(),
                scope(recorded.execution()),
                indices()
            );
            FetchRequest.ShardDocs lastRead = freedAfterFetch(SHARD);
            ShardSearchContextId readAgain = new ShardSearchContextId("session", 8);
            recorded.arrived(lastRead.contextId(), readAgain);

            client.fetch(NODE, "", List.of(lastRead), List.of(), ActionListener.noop());
            client.fetchEnded();

            assertThat(recorded.transport().freed(), equalTo(Set.of(readAgain)));
            recorded.lease().close();
        } finally {
            response.decRef();
        }
    }

    /**
     * A request that failed as a whole may never have reached its node, so the lease still frees the contexts it read for
     * the last time.
     */
    public void testAFailedLastFetchLeavesItsContextsToTheLease() {
        RecordedLease recorded = leaseThatRecordsFrees();
        QueryFetchClient client = new QueryFetchClient(
            (target, request, parentTask, listener) -> listener.onFailure(new IllegalStateException("not connected")),
            threadContext,
            directory(),
            scope(recorded.execution()),
            indices()
        );
        FetchRequest.ShardDocs lastRead = freedAfterFetch(SHARD);
        recorded.arrived(lastRead.contextId());

        client.fetch(NODE, "", List.of(lastRead), List.of(), ActionListener.noop());
        client.fetchEnded();

        assertThat(recorded.transport().freed(), equalTo(Set.of(lastRead.contextId())));
        recorded.lease().close();
    }

    /**
     * A lease and its execution, and the transport that records what the lease frees.
     */
    private record RecordedLease(FetchContextLease lease, FetchContextLease.Execution execution, RecordingFetchContextTransport transport) {
        /**
         * Rows read through the contexts {@code ids} of {@link #FETCH_NODE} reached the coordinator.
         */
        void arrived(ShardSearchContextId... ids) {
            for (ShardSearchContextId id : ids) {
                execution.arrived(FETCH_NODE, id);
            }
        }
    }

    private RecordedLease leaseThatRecordsFrees() {
        RecordingFetchContextTransport transport = new RecordingFetchContextTransport();
        FetchContextLease lease = new FetchContextLease(
            new FetchContextLeases(null, null, null, directory()),
            transport,
            rootTask,
            threadContext.newRestorableContext(false),
            TimeValue.timeValueMinutes(5)
        );
        return new RecordedLease(lease, lease.newExecution(), transport);
    }

    private static FetchRequest.ShardDocs freedAfterFetch(FetchRequest.ShardDocs shard) {
        return new FetchRequest.ShardDocs(shard.shardId(), shard.contextId(), true, shard.segments(), shard.docs());
    }

    /**
     * The fetch phase reads the local cluster only. The directory refuses a node of a remote cluster first, so a fetch for
     * one is a bug, which fails the fetch rather than sending a request with the index expressions of another cluster.
     */
    public void testAFetchFromARemoteClusterIsRefused() {
        QueryFetchClient client = client((target, request, parentTask, listener) -> fail("nothing to send"));

        IllegalStateException e = expectThrows(
            IllegalStateException.class,
            () -> client.fetch(NODE, "remote", List.of(SHARD), List.of(), ActionListener.noop())
        );

        assertThat(e.getMessage(), equalTo("the fetch phase reads the local cluster only, not [remote]"));
        assertThat(drivers.completed, empty());
    }

    private QueryFetchClient client(QueryFetchClient.Sender sender) {
        return new QueryFetchClient(sender, threadContext, directory(), scope(), indices());
    }

    /**
     * The names of the indices of a {@code FROM logs-*} over the index of {@link #SHARD}.
     */
    private static FetchIndices indices() {
        ProjectMetadata project = ProjectMetadata.builder(ProjectId.DEFAULT)
            .put(IndexMetadata.builder("logs-1").settings(indexSettings(IndexVersion.current(), 1, 0)))
            .build();
        return FetchIndices.resolve(TestIndexNameExpressionResolver.newInstance(), project, List.of("logs-*"));
    }

    private QueryFetchScope scope() {
        // the client holds no context in these tests, so the lease never sends a request
        return scope(
            new FetchContextLease(
                new FetchContextLeases(null, null, null, directory()),
                new RecordingFetchContextTransport(),
                rootTask,
                threadContext.newRestorableContext(false),
                TimeValue.timeValueMinutes(5)
            ).newExecution()
        );
    }

    private QueryFetchScope scope(FetchContextLease.Execution fetchContexts) {
        return new QueryFetchScope(rootTask, "query-session", EsqlTestUtils.TEST_CFG, drivers, fetchContexts);
    }

    private DiscoveryNodes nodes() {
        return DiscoveryNodes.builder().add(NODE).build();
    }

    private FetchNodeDirectory directory() {
        return new FetchNodeDirectory(this::nodes);
    }

    private record Sent(DiscoveryNode target, FetchRequest request, Task parentTask) {}

    /**
     * Stands in for the compute listener of the query, which counts the drivers of each listener it hands out.
     */
    private static class QueryDrivers implements Supplier<ActionListener<DriverCompletionInfo>> {
        private final List<DriverCompletionInfo> completed = new ArrayList<>();

        @Override
        public ActionListener<DriverCompletionInfo> get() {
            return ActionListener.assertOnce(ActionListener.wrap(completed::add, e -> { throw new AssertionError(e); }));
        }
    }
}
