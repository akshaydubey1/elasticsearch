/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.esql.action;

import org.apache.logging.log4j.Level;
import org.apache.lucene.util.BytesRef;
import org.elasticsearch.action.ActionFuture;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.DocWriteRequest;
import org.elasticsearch.action.bulk.BatchIndexingEnabled;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkRequestBuilder;
import org.elasticsearch.action.bulk.ShardBatchIndexer;
import org.elasticsearch.action.bulk.TransportBulkAction;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.support.ActionFilter;
import org.elasticsearch.action.support.ActionFilterChain;
import org.elasticsearch.action.support.SubscribableListener;
import org.elasticsearch.action.support.WriteRequest;
import org.elasticsearch.client.internal.Client;
import org.elasticsearch.client.internal.OriginSettingClient;
import org.elasticsearch.cluster.routing.ShardRouting;
import org.elasticsearch.common.breaker.CircuitBreakingException;
import org.elasticsearch.common.io.stream.NamedWriteableAwareStreamInput;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.compute.data.BlockFactory;
import org.elasticsearch.compute.data.BlockStreamInput;
import org.elasticsearch.compute.data.LongBlock;
import org.elasticsearch.compute.data.Page;
import org.elasticsearch.compute.test.TestBlockFactory;
import org.elasticsearch.core.TimeValue;
import org.elasticsearch.escf.EscfBatch;
import org.elasticsearch.escf.EscfBatchBuilder;
import org.elasticsearch.escf.EscfRowBuffer;
import org.elasticsearch.indices.breaker.HierarchyCircuitBreakerService;
import org.elasticsearch.plugins.ActionPlugin;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.test.MockLog;
import org.elasticsearch.test.junit.annotations.TestLogging;
import org.elasticsearch.transport.BytesRefRecycler;
import org.elasticsearch.xcontent.XContentType;
import org.elasticsearch.xpack.core.ClientHelper;
import org.elasticsearch.xpack.core.esql.EsqlStreamResultsIndex;
import org.elasticsearch.xpack.esql.plugin.QueryPragmas;
import org.elasticsearch.xpack.esql.plugin.StoredPagesService;
import org.elasticsearch.xpack.esql.plugin.StoredResultMetadata;
import org.elasticsearch.xpack.esql.plugin.TransportReadStreamPagesAction;
import org.elasticsearch.xpack.esql.plugin.TransportReadStreamPagesAction.StoredPage;
import org.junit.After;
import org.junit.Before;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.IntStream;
import java.util.stream.LongStream;

import static org.elasticsearch.test.hamcrest.ElasticsearchAssertions.assertAcked;
import static org.elasticsearch.test.hamcrest.ElasticsearchAssertions.assertNoFailures;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

/**
 * Streaming queries that store their result with {@code store=true}.
 */
public class StoredStreamIT extends AbstractEsqlIntegTestCase {

    @Before
    public void requireStoredResults() {
        assumeTrue("stored results are behind a feature flag", EsqlStreamResultsIndex.FEATURE_FLAG.isEnabled());
        assumeTrue("storing needs batch indexing, behind a feature flag", BatchIndexingEnabled.FEATURE_FLAG.isEnabled());
    }

    @Override
    protected Settings nodeSettings(int nodeOrdinal, Settings otherSettings) {
        Settings.Builder settings = Settings.builder()
            .put(super.nodeSettings(nodeOrdinal, otherSettings))
            // reads are charged to the request breaker, which the test cluster may otherwise make a no-op
            .put(
                HierarchyCircuitBreakerService.REQUEST_CIRCUIT_BREAKER_TYPE_SETTING.getKey(),
                HierarchyCircuitBreakerService.REQUEST_CIRCUIT_BREAKER_TYPE_SETTING.getDefault(Settings.EMPTY)
            );
        // nodes refuse the setting while its feature flag is off, and the tests are skipped then
        if (BatchIndexingEnabled.FEATURE_FLAG.isEnabled()) {
            settings.put(BatchIndexingEnabled.BATCH_INDEXING.getKey(), true);
        }
        return settings.build();
    }

    @Override
    protected Collection<Class<? extends Plugin>> nodePlugins() {
        List<Class<? extends Plugin>> plugins = new ArrayList<>(super.nodePlugins());
        plugins.add(RefreshSignalPlugin.class);
        return Collections.unmodifiableList(plugins);
    }

    /**
     * Signals the next bulk that refreshes: the last bulk of a stored result, which makes all its pages visible.
     */
    public static class RefreshSignalPlugin extends Plugin implements ActionPlugin {
        private static final AtomicReference<SubscribableListener<Void>> NEXT_REFRESH = new AtomicReference<>();

        static SubscribableListener<Void> nextRefresh() {
            SubscribableListener<Void> refreshed = new SubscribableListener<>();
            NEXT_REFRESH.set(refreshed);
            return refreshed;
        }

        @Override
        public List<ActionFilter> getActionFilters() {
            return List.of(new ActionFilter() {
                @Override
                public int order() {
                    return 0;
                }

                @Override
                public <Request extends ActionRequest, Response extends ActionResponse> void apply(
                    Task task,
                    String action,
                    Request request,
                    ActionListener<Response> listener,
                    ActionFilterChain<Request, Response> chain
                ) {
                    if (action.equals(TransportBulkAction.NAME)
                        && ((BulkRequest) request).getRefreshPolicy() == WriteRequest.RefreshPolicy.IMMEDIATE) {
                        listener = ActionListener.runAfter(listener, () -> {
                            SubscribableListener<Void> refreshed = NEXT_REFRESH.getAndSet(null);
                            if (refreshed != null) {
                                refreshed.onResponse(null);
                            }
                        });
                    }
                    chain.proceed(task, action, request, listener);
                }
            });
        }
    }

    @After
    public void clearWaitingListeners() {
        for (StoredPagesService service : internalCluster().getInstances(StoredPagesService.class)) {
            service.setWaitingListener(streamId -> {});
        }
    }

    private int indexDocs() {
        int numDocs = between(100, 300);
        assertAcked(client().admin().indices().prepareCreate("test").setMapping("v", "type=long"));
        BulkRequestBuilder bulk = client().prepareBulk().setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
        for (int i = 0; i < numDocs; i++) {
            bulk.add(prepareIndex("test").setSource("v", i));
        }
        assertNoFailures(bulk.get());
        return numDocs;
    }

    private static final TimeValue KEEP_ALIVE = TimeValue.timeValueHours(3);

    private EsqlStreamQueryAction.ResultStream stream(boolean store, StreamQueryTestUtils.CountingStreamSubscriber subscriber) {
        EsqlQueryRequest source = EsqlQueryRequest.syncEsqlQueryRequest("FROM test | KEEP v | LIMIT 10000");
        // small pages, so that a result is stored as many pages
        source.pragmas(new QueryPragmas(Settings.builder().put(QueryPragmas.PAGE_SIZE.getKey(), between(1, 10)).build()));
        source.acceptedPragmaRisks(true);
        AtomicReference<EsqlStreamQueryAction.ResultStream> startRef = new AtomicReference<>();
        EsqlStreamQueryRequest request = new EsqlStreamQueryRequest(source, ActionListener.wrap(resultStream -> {
            startRef.set(resultStream);
            resultStream.publisher().subscribe(subscriber);
        }, subscriber.failure::set), false);
        if (store) {
            request.store(true).storeKeepAlive(KEEP_ALIVE);
        }
        ActionFuture<ActionResponse.Empty> future = client().execute(EsqlStreamQueryAction.INSTANCE, request);
        future.actionGet(TEST_REQUEST_TIMEOUT);
        safeAwait(subscriber.completed);
        assertThat(subscriber.failure.get(), nullValue());
        return startRef.get();
    }

    public void testNotStoredByDefault() {
        int numDocs = indexDocs();
        var subscriber = new StreamQueryTestUtils.CountingStreamSubscriber();
        var resultStream = stream(false, subscriber);
        assertThat(subscriber.rowCount.get(), equalTo(numDocs));
        assertThat(resultStream.id(), nullValue());
        assertFalse(indexExists(EsqlStreamResultsIndex.INDEX));
    }

    public void testStoreRequiresBatchIndexing() {
        indexDocs();
        updateClusterSettings(Settings.builder().put(BatchIndexingEnabled.BATCH_INDEXING.getKey(), false));
        try {
            EsqlQueryRequest source = EsqlQueryRequest.syncEsqlQueryRequest("FROM test | KEEP v");
            EsqlStreamQueryRequest request = new EsqlStreamQueryRequest(source, ActionListener.noop(), false).store(true);
            IllegalArgumentException e = expectThrows(
                IllegalArgumentException.class,
                () -> client().execute(EsqlStreamQueryAction.INSTANCE, request).actionGet(TEST_REQUEST_TIMEOUT)
            );
            assertThat(e.getMessage(), containsString(BatchIndexingEnabled.BATCH_INDEXING.getKey()));
        } finally {
            updateClusterSettings(Settings.builder().putNull(BatchIndexingEnabled.BATCH_INDEXING.getKey()));
        }
    }

    @TestLogging(value = "org.elasticsearch.action.bulk.ShardBatchIndexer:TRACE", reason = "checks that pages take the batch path")
    public void testStored() throws Exception {
        int numDocs = indexDocs();
        var subscriber = new StreamQueryTestUtils.CountingStreamSubscriber();
        AtomicReference<String> storedId = new AtomicReference<>();
        long before = System.currentTimeMillis();
        MockLog.assertThatLogger(
            () -> storedId.set(storeResult(subscriber)),
            ShardBatchIndexer.class,
            new MockLog.SeenEventExpectation(
                "batch path",
                ShardBatchIndexer.class.getCanonicalName(),
                Level.TRACE,
                "batch indexed [*] operations on primary shard*"
            )
        );
        assertThat(subscriber.rowCount.get(), equalTo(numDocs));
        String docId = storedId.get();

        NamedWriteableRegistry registry = internalCluster().getInstance(NamedWriteableRegistry.class);
        StoredResultMetadata metadata = metadata(docId, registry);
        assertThat(metadata.status(), equalTo(StoredResultMetadata.Status.COMPLETED));
        assertThat(metadata.rowCount(), equalTo((long) numDocs));
        assertThat(metadata.pageCount(), greaterThan(1));
        assertThat(metadata.columns().get(0).name(), equalTo("v"));
        // the result is kept for the keep_alive of its request; the cluster's clock is cached, so it can lag by a little
        long expirationTime = readPages(docId, 0, 1).get(0).expirationTime();
        long slack = TimeValue.timeValueMinutes(1).millis();
        assertThat(expirationTime, greaterThanOrEqualTo(before + KEEP_ALIVE.millis() - slack));
        assertThat(expirationTime, lessThanOrEqualTo(System.currentTimeMillis() + KEEP_ALIVE.millis() + slack));

        BlockFactory blockFactory = TestBlockFactory.getNonBreakingInstance();
        List<Long> values = new ArrayList<>();
        List<StoredPage> pages = readPages(docId, 1, metadata.pageCount() + 1);
        assertThat(pages.size(), equalTo(metadata.pageCount()));
        long expectedFirstRow = 0;
        for (int i = 0; i < pages.size(); i++) {
            StoredPage stored = pages.get(i);
            assertThat(stored.seq(), equalTo(i + 1));
            assertThat(stored.firstRow(), equalTo(expectedFirstRow));
            try (BlockStreamInput in = new BlockStreamInput(input(stored, registry), blockFactory)) {
                Page page = new Page(in);
                try {
                    assertThat(page.getPositionCount(), equalTo(stored.rowCount()));
                    LongBlock block = page.getBlock(0);
                    for (int p = 0; p < block.getPositionCount(); p++) {
                        values.add(block.getLong(block.getFirstValueIndex(p)));
                    }
                } finally {
                    page.releaseBlocks();
                }
            }
            expectedFirstRow += stored.rowCount();
        }
        Collections.sort(values);
        assertThat(values, equalTo(LongStream.range(0, numDocs).boxed().toList()));
    }

    /**
     * A read past the last page of a finished result answers at once that the result ended: its wait is longer than the test
     * waits for the answer.
     */
    public void testReadPastEndedResultDoesNotWait() throws Exception {
        indexDocs();
        String docId = storeResult(new StreamQueryTestUtils.CountingStreamSubscriber());
        StoredResultMetadata metadata = metadata(docId, internalCluster().getInstance(NamedWriteableRegistry.class));
        TransportReadStreamPagesAction.Response response = client().execute(
            TransportReadStreamPagesAction.TYPE,
            new TransportReadStreamPagesAction.Request(docId, metadata.pageCount() + 1, 1, Long.MAX_VALUE, TimeValue.timeValueMinutes(1))
        ).actionGet(TEST_REQUEST_TIMEOUT);
        try {
            assertTrue(response.resultEnded());
            assertThat(response.pages().size(), equalTo(0));
        } finally {
            response.decRef();
        }
    }

    /**
     * Concurrent results spread over the shards of the pages index, and its shards over the nodes, while all the documents
     * of one result stay on the shard its id routes to.
     */
    public void testResultsSpreadOverShards() throws Exception {
        internalCluster().ensureAtLeastNumDataNodes(2);
        int numDocs = indexDocs();
        int results = between(8, 12);
        NamedWriteableRegistry registry = internalCluster().getInstance(NamedWriteableRegistry.class);
        for (int r = 0; r < results; r++) {
            String docId = storeResult(new StreamQueryTestUtils.CountingStreamSubscriber());
            StoredResultMetadata metadata = metadata(docId, registry);
            assertThat(metadata.status(), equalTo(StoredResultMetadata.Status.COMPLETED));
            List<StoredPage> pages = readPages(docId, 1, metadata.pageCount());
            assertThat(pages.size(), equalTo(metadata.pageCount()));
            assertThat(pages.stream().mapToLong(StoredPage::rowCount).sum(), equalTo((long) numDocs));
        }

        int shardsWithPages = 0;
        for (var shard : client().admin().indices().prepareStats(EsqlStreamResultsIndex.INDEX).setDocs(true).get().getShards()) {
            if (shard.getShardRouting().primary() && shard.getStats().getDocs().getCount() > 0) {
                shardsWithPages++;
            }
        }
        assertThat(shardsWithPages, greaterThan(1));

        var routingTable = clusterAdmin().prepareState(TEST_REQUEST_TIMEOUT).get().getState().routingTable();
        long nodes = routingTable.allShards(EsqlStreamResultsIndex.INDEX)
            .stream()
            .filter(ShardRouting::primary)
            .map(ShardRouting::currentNodeId)
            .distinct()
            .count();
        assertThat(nodes, greaterThan(1L));
    }

    /**
     * Writes {@code blobs} as the pages of a result from {@code fromSeq}, in one pre-built batch, without refreshing.
     */
    private void writePages(String docId, int fromSeq, List<BytesRef> blobs) {
        Client client = new OriginSettingClient(client(), ClientHelper.ESQL_ORIGIN);
        try (EscfBatchBuilder builder = new EscfBatchBuilder(BytesRefRecycler.NON_RECYCLING_INSTANCE)) {
            BulkRequestBuilder bulk = client.prepareBulk();
            List<IndexRequest> requests = new ArrayList<>();
            byte[] streamId = docId.getBytes(StandardCharsets.UTF_8);
            for (int i = 0; i < blobs.size(); i++) {
                int seq = fromSeq + i;
                EscfRowBuffer row = builder.beginRow();
                row.stringField(EsqlStreamResultsIndex.STREAM_ID_FIELD, streamId, 0, streamId.length);
                row.longField(EsqlStreamResultsIndex.PAGE_SEQ_FIELD, seq);
                row.longField(EsqlStreamResultsIndex.FIRST_ROW_FIELD, (seq - 1) * 10L);
                row.longField(EsqlStreamResultsIndex.ROW_COUNT_FIELD, 10);
                row.longField(EsqlStreamResultsIndex.TRANSPORT_VERSION_FIELD, 1);
                row.binaryField(EsqlStreamResultsIndex.PAGE_FIELD, blobs.get(i));
                row.finishRow();
                builder.commit(0);
                requests.add(
                    new IndexRequest(EsqlStreamResultsIndex.INDEX).id(EsqlStreamResultsIndex.pageDocId(docId, seq))
                        .routing(docId)
                        .opType(DocWriteRequest.OpType.CREATE)
                );
            }
            EscfBatch batch = builder.buildPartition(0);
            for (int r = 0; r < requests.size(); r++) {
                requests.get(r).indexSource().setSourceRow(batch, r, XContentType.JSON);
                bulk.add(requests.get(r));
            }
            bulk.setPreBuiltBatches(Map.of(EsqlStreamResultsIndex.INDEX, batch));
            assertNoFailures(bulk.get());
        }
    }

    private static List<BytesRef> randomBlobs(int count) {
        List<BytesRef> blobs = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            blobs.add(new BytesRef(randomByteArrayOfLength(between(1, 1024))));
        }
        return blobs;
    }

    /**
     * A read sees pages without a refresh of the index: it refreshes its shard locally, and waits for pages not indexed yet.
     */
    public void testReadWaitsForNewPages() throws Exception {
        String docId = randomAlphaOfLength(12);
        List<BytesRef> first = randomBlobs(between(1, 3));
        writePages(docId, 1, first);
        // indexed but never refreshed
        List<StoredPage> visible = pagesOf(
            client().execute(
                TransportReadStreamPagesAction.TYPE,
                new TransportReadStreamPagesAction.Request(docId, 1, first.size(), Long.MAX_VALUE, TimeValue.timeValueSeconds(30))
            )
        );
        assertThat(visible.size(), equalTo(first.size()));

        int nextSeq = first.size() + 1;
        ActionFuture<TransportReadStreamPagesAction.Response> waiting = startWaitingRead(
            docId,
            new TransportReadStreamPagesAction.Request(docId, nextSeq, 10, Long.MAX_VALUE, TimeValue.timeValueSeconds(30))
        );
        assertFalse(waiting.isDone());

        List<BytesRef> next = randomBlobs(between(1, 3));
        writePages(docId, nextSeq, next);
        List<StoredPage> woken = pagesOf(waiting);
        assertThat(woken.size(), equalTo(next.size()));
        for (int i = 0; i < next.size(); i++) {
            assertThat(woken.get(i).seq(), equalTo(nextSeq + i));
            assertThat(woken.get(i).bytes().toBytesRef(), equalTo(next.get(i)));
        }

        // the wait times out
        List<StoredPage> timedOut = pagesOf(
            client().execute(
                TransportReadStreamPagesAction.TYPE,
                new TransportReadStreamPagesAction.Request(docId, nextSeq + next.size(), 10, Long.MAX_VALUE, TimeValue.timeValueMillis(100))
            )
        );
        assertThat(timedOut.size(), equalTo(0));
        for (StoredPagesService service : internalCluster().getInstances(StoredPagesService.class)) {
            assertThat(service.waitingReads(), equalTo(0));
        }
    }

    /**
     * Reading from a row starts at the page that holds it, or waits for the page that will hold it. The pages written by
     * {@link #writePages} hold 10 rows each.
     */
    public void testReadFromRow() throws Exception {
        String docId = randomAlphaOfLength(12);
        writePages(docId, 1, randomBlobs(4));
        refreshPages();
        assertThat(firstSeqFromRow(docId, 0), equalTo(1));
        assertThat(firstSeqFromRow(docId, 9), equalTo(1));
        assertThat(firstSeqFromRow(docId, 10), equalTo(2));
        assertThat(firstSeqFromRow(docId, 39), equalTo(4));
        assertThat(firstSeqFromRow(docId, 40), equalTo(-1));

        ActionFuture<TransportReadStreamPagesAction.Response> waiting = startWaitingRead(
            docId,
            TransportReadStreamPagesAction.Request.fromRow(docId, 45, 1, Long.MAX_VALUE, TimeValue.timeValueSeconds(30))
        );
        writePages(docId, 5, randomBlobs(1));
        List<StoredPage> pages = pagesOf(waiting);
        assertThat(pages.size(), equalTo(1));
        assertThat(pages.get(0).seq(), equalTo(5));
    }

    private int firstSeqFromRow(String docId, long row) {
        List<StoredPage> pages = pagesOf(
            client().execute(
                TransportReadStreamPagesAction.TYPE,
                TransportReadStreamPagesAction.Request.fromRow(docId, row, 1, Long.MAX_VALUE, TimeValue.ZERO)
            )
        );
        return pages.isEmpty() ? -1 : pages.get(0).seq();
    }

    /**
     * Streams a query that stores its result, and returns the id of the result once all its pages are visible.
     */
    private String storeResult(StreamQueryTestUtils.CountingStreamSubscriber subscriber) {
        SubscribableListener<Void> refreshed = RefreshSignalPlugin.nextRefresh();
        String id = stream(true, subscriber).id();
        assertThat(id, notNullValue());
        safeAwait(refreshed);
        return id;
    }

    private StoredResultMetadata metadata(String docId, NamedWriteableRegistry registry) throws IOException {
        List<StoredPage> first = readPages(docId, 0, 1);
        assertThat(first.size(), equalTo(1));
        return new StoredResultMetadata(input(first.get(0), registry));
    }

    /**
     * Completes the next time a read waits for pages of the result, having found none.
     */
    private SubscribableListener<Void> onWaiting(String docId) {
        SubscribableListener<Void> waiting = new SubscribableListener<>();
        for (StoredPagesService service : internalCluster().getInstances(StoredPagesService.class)) {
            service.setWaitingListener(streamId -> {
                if (streamId.equals(docId)) {
                    waiting.onResponse(null);
                }
            });
        }
        return waiting;
    }

    /**
     * Sends a read and returns once it waits on its shard.
     */
    private ActionFuture<TransportReadStreamPagesAction.Response> startWaitingRead(
        String docId,
        TransportReadStreamPagesAction.Request request
    ) {
        SubscribableListener<Void> waiting = onWaiting(docId);
        ActionFuture<TransportReadStreamPagesAction.Response> read = client().execute(TransportReadStreamPagesAction.TYPE, request);
        safeAwait(waiting);
        return read;
    }

    /**
     * A read takes pages while they fit in its budget, and always the first.
     */
    public void testReadStopsAtByteBudget() {
        String docId = randomAlphaOfLength(12);
        int pageBytes = 1024;
        int pageCount = between(2, 8);
        writePages(docId, 1, sameSizeBlobs(pageCount, pageBytes));
        refreshPages();

        int fitting = between(1, pageCount);
        long maxBytes = fitting * pageBytes + between(0, pageBytes - 1);
        assertThat(read(new TransportReadStreamPagesAction.Request(docId, 1, 100, maxBytes, TimeValue.ZERO)).size(), equalTo(fitting));
        assertThat(read(new TransportReadStreamPagesAction.Request(docId, 1, 100, 0, TimeValue.ZERO)).size(), equalTo(1));
    }

    /**
     * A read ends before a page that is not visible, so that the pages after it are read once it is.
     */
    public void testReadStopsAtMissingPage() {
        String docId = randomAlphaOfLength(12);
        int before = between(1, 4);
        writePages(docId, 1, randomBlobs(before));
        writePages(docId, before + 2, randomBlobs(between(1, 4)));
        refreshPages();

        List<StoredPage> pages = read(new TransportReadStreamPagesAction.Request(docId, 1, 100, Long.MAX_VALUE, TimeValue.ZERO));
        assertThat(pages.stream().map(StoredPage::seq).toList(), equalTo(IntStream.rangeClosed(1, before).boxed().toList()));
    }

    /**
     * The pages of a read are charged to the request breaker: a page that trips it ends the read, unless it is the first.
     */
    public void testReadChargesRequestBreaker() {
        String docId = randomAlphaOfLength(12);
        int pageBytes = 64 * 1024;
        writePages(docId, 1, sameSizeBlobs(between(2, 4), pageBytes));
        refreshPages();
        TransportReadStreamPagesAction.Request request = new TransportReadStreamPagesAction.Request(
            docId,
            1,
            100,
            Long.MAX_VALUE,
            TimeValue.ZERO
        );
        try {
            setRequestBreakerLimit(pageBytes * 3 / 2 + "b");
            assertThat(read(request).size(), equalTo(1));

            setRequestBreakerLimit(pageBytes / 2 + "b");
            expectThrows(CircuitBreakingException.class, () -> read(request));
        } finally {
            setRequestBreakerLimit(null);
        }
    }

    private void setRequestBreakerLimit(String limit) {
        updateClusterSettings(Settings.builder().put(HierarchyCircuitBreakerService.REQUEST_CIRCUIT_BREAKER_LIMIT_SETTING.getKey(), limit));
    }

    private void refreshPages() {
        new OriginSettingClient(client(), ClientHelper.ESQL_ORIGIN).admin().indices().prepareRefresh(EsqlStreamResultsIndex.INDEX).get();
    }

    private static List<BytesRef> sameSizeBlobs(int count, int bytes) {
        List<BytesRef> blobs = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            blobs.add(new BytesRef(randomByteArrayOfLength(bytes)));
        }
        return blobs;
    }

    /**
     * Returns the pages of a read and releases the response, which the future holds a reference to.
     */
    private static List<StoredPage> pagesOf(ActionFuture<TransportReadStreamPagesAction.Response> future) {
        TransportReadStreamPagesAction.Response response = future.actionGet(TEST_REQUEST_TIMEOUT);
        try {
            return response.pages();
        } finally {
            response.decRef();
        }
    }

    private List<StoredPage> read(TransportReadStreamPagesAction.Request request) {
        return pagesOf(client().execute(TransportReadStreamPagesAction.TYPE, request));
    }

    private List<StoredPage> readPages(String docId, int fromSeq, int maxPages) {
        return read(new TransportReadStreamPagesAction.Request(docId, fromSeq, maxPages));
    }

    private static StreamInput input(StoredPage stored, NamedWriteableRegistry registry) throws IOException {
        StreamInput in = new NamedWriteableAwareStreamInput(stored.bytes().streamInput(), registry);
        in.setTransportVersion(stored.transportVersion());
        return in;
    }
}
