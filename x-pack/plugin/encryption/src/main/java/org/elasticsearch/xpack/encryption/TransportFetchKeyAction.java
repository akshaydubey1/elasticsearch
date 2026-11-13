/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */
package org.elasticsearch.xpack.encryption;

import org.elasticsearch.action.ActionType;
import org.elasticsearch.action.FailedNodeException;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.TransportAction;
import org.elasticsearch.action.support.nodes.BaseNodeResponse;
import org.elasticsearch.action.support.nodes.BaseNodesRequest;
import org.elasticsearch.action.support.nodes.BaseNodesResponse;
import org.elasticsearch.action.support.nodes.TransportNodesAction;
import org.elasticsearch.cluster.ClusterName;
import org.elasticsearch.cluster.ClusterState;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.Strings;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.core.Nullable;
import org.elasticsearch.injection.guice.Inject;
import org.elasticsearch.logging.LogManager;
import org.elasticsearch.logging.Logger;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.AbstractTransportRequest;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.xpack.encryption.ProjectEncryptionKeyMetadata.KeyEntry;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * Asks nodes for the project encryption keys they hold on disk for a given active key. An elected master that could not read the key
 * from its own disk uses this to get it from any node that can, instead of leaving encryption unavailable on every node. The keys travel
 * in plaintext over the TLS-protected transport channel, as they do in every cluster state publication.
 */
public class TransportFetchKeyAction extends TransportNodesAction<
    TransportFetchKeyAction.Request,
    TransportFetchKeyAction.Response,
    TransportFetchKeyAction.NodeRequest,
    TransportFetchKeyAction.NodeResponse,
    Void> {

    public static final ActionType<Response> TYPE = new ActionType<>("internal:cluster/encryption/key/fetch");

    private static final Logger logger = LogManager.getLogger(TransportFetchKeyAction.class);

    private final PasswordPekEncryption pekEncryption;
    private final ProjectEncryptionKeyService pekService;

    @Inject
    public TransportFetchKeyAction(
        ClusterService clusterService,
        TransportService transportService,
        ActionFilters actionFilters,
        PasswordPekEncryption pekEncryption,
        ProjectEncryptionKeyService pekService
    ) {
        super(
            TYPE.name(),
            clusterService,
            transportService,
            actionFilters,
            NodeRequest::new,
            // unwrapping derives a key from the password
            transportService.getThreadPool().executor(ThreadPool.Names.GENERIC)
        );
        this.pekEncryption = pekEncryption;
        this.pekService = pekService;
    }

    @Override
    protected Response newResponse(Request request, List<NodeResponse> responses, List<FailedNodeException> failures) {
        return new Response(clusterService.getClusterName(), responses, failures);
    }

    @Override
    protected NodeRequest newNodeRequest(Request request) {
        return new NodeRequest(request.activeKeyId);
    }

    @Override
    protected NodeResponse newNodeResponse(StreamInput in, DiscoveryNode node) throws IOException {
        return new NodeResponse(in);
    }

    @Override
    protected NodeResponse nodeOperation(NodeRequest request, Task task) {
        DiscoveryNode localNode = transportService.getLocalNode();
        ClusterState state = clusterService.state();
        ProjectEncryptionKeyMetadata published = pekService.metadataIn(state);
        // hand out the key only to recover it: to the elected master, while the metadata it published holds no key
        if (task.getParentTaskId().isSet() == false
            || task.getParentTaskId().getNodeId().equals(state.nodes().getMasterNodeId()) == false
            || published == null
            || published.isUnwrapFailed() == false
            || request.activeKeyId.equals(published.getActiveKeyId()) == false) {
            logger.debug(
                "not handing out project encryption key [{}]: the elected master did not ask for it to recover",
                request.activeKeyId
            );
            return new NodeResponse(localNode, null);
        }
        try {
            ProjectEncryptionKeyMetadata keys = pekEncryption.gatewayKeysFor(request.activeKeyId);
            return keys == null
                ? new NodeResponse(localNode, null)
                : new NodeResponse(
                    localNode,
                    new Keys(keys.getKeys(), keys.getActiveKeyId(), keys.getPasswordId(), keys.getHandlerKeyIds())
                );
        } catch (Exception e) {
            logger.debug(() -> Strings.format("cannot unwrap this node's copy of project encryption key [%s]", request.activeKeyId), e);
            return new NodeResponse(localNode, null);
        }
    }

    /** The plaintext keys a node holds for the requested active key. */
    record Keys(Map<String, KeyEntry> keys, String activeKeyId, String passwordId, Map<String, String> handlerKeyIds) {
        Keys(StreamInput in) throws IOException {
            this(
                in.readImmutableMap(StreamInput::readString, KeyEntry::new),
                in.readString(),
                in.readString(),
                in.readImmutableMap(StreamInput::readString, StreamInput::readString)
            );
        }

        void writeTo(StreamOutput out) throws IOException {
            out.writeMap(keys, StreamOutput::writeString, (o, e) -> e.writeTo(o));
            out.writeString(activeKeyId);
            out.writeString(passwordId);
            out.writeMap(handlerKeyIds, StreamOutput::writeString, StreamOutput::writeString);
        }
    }

    public static class Request extends BaseNodesRequest {
        private final String activeKeyId;

        private final List<DiscoveryNode> nodes;

        public Request(String activeKeyId, DiscoveryNode... nodes) {
            super(nodes);
            this.activeKeyId = activeKeyId;
            this.nodes = List.of(nodes);
        }

        String activeKeyId() {
            return activeKeyId;
        }

        List<DiscoveryNode> nodes() {
            return nodes;
        }
    }

    public static class Response extends BaseNodesResponse<NodeResponse> {
        Response(ClusterName clusterName, List<NodeResponse> nodes, List<FailedNodeException> failures) {
            super(clusterName, nodes, failures);
        }

        @Override
        protected List<NodeResponse> readNodesFrom(StreamInput in) {
            return TransportAction.localOnly();
        }

        @Override
        protected void writeNodesTo(StreamOutput out, List<NodeResponse> nodes) {
            TransportAction.localOnly();
        }
    }

    public static class NodeRequest extends AbstractTransportRequest {
        private final String activeKeyId;

        NodeRequest(String activeKeyId) {
            this.activeKeyId = activeKeyId;
        }

        NodeRequest(StreamInput in) throws IOException {
            super(in);
            this.activeKeyId = in.readString();
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            super.writeTo(out);
            out.writeString(activeKeyId);
        }
    }

    public static class NodeResponse extends BaseNodeResponse {
        @Nullable
        private final Keys keys;

        NodeResponse(DiscoveryNode node, @Nullable Keys keys) {
            super(node);
            this.keys = keys;
        }

        NodeResponse(StreamInput in) throws IOException {
            super(in);
            this.keys = in.readOptional(Keys::new);
        }

        @Nullable
        Keys keys() {
            return keys;
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            super.writeTo(out);
            out.writeOptional((o, k) -> k.writeTo(o), keys);
        }
    }
}
