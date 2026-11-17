/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.esql.fetch;

import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.project.ProjectResolver;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.compute.operator.Operator;
import org.elasticsearch.xpack.esql.plan.physical.FetchExec;
import org.elasticsearch.xpack.esql.planner.FetchOperatorProvider;

/**
 * The entry point to the runtime of the fetch phase on a coordinator. ES|QL code outside this package gets the operators
 * and the leases of the fetch phase from it, so the runtime can change without touching that code.
 */
public interface FetchPhaseServices {
    /**
     * The fetch operators of the query that {@code scope} describes, on its coordinator.
     */
    FetchOperatorProvider operatorProvider(QueryFetchScope scope);

    /**
     * The leases of the fetch contexts of the queries this node coordinates.
     */
    FetchContextLeases leases();

    /**
     * The runtime of this node: a {@link FetchOperator} for each {@link FetchExec} that sends its requests through
     * {@code fetchService} and the leases of {@code leases}. Its requests name the indices that the expressions of the
     * {@code FetchExec} resolve to in the project of this node.
     */
    static FetchPhaseServices create(
        FetchContextLeases leases,
        FetchService fetchService,
        ClusterService clusterService,
        ProjectResolver projectResolver,
        IndexNameExpressionResolver indexNameExpressionResolver
    ) {
        return new FetchPhaseServices() {
            @Override
            public FetchOperatorProvider operatorProvider(QueryFetchScope scope) {
                return new FetchOperatorProvider() {
                    @Override
                    public Operator.OperatorFactory fetchOperator(FetchExec exec, int docChannel) {
                        FetchIndices indices = FetchIndices.resolve(
                            indexNameExpressionResolver,
                            projectResolver.getProjectMetadata(clusterService.state()),
                            exec.originalIndices()
                        );
                        return FetchOperator.Factory.forExec(
                            exec,
                            docChannel,
                            new QueryFetchClient(
                                fetchService::sendFetch,
                                clusterService.threadPool().getThreadContext(),
                                leases.nodes(),
                                scope,
                                indices
                            )
                        );
                    }

                    @Override
                    public boolean receivesDetachedDocuments() {
                        return true;
                    }
                };
            }

            @Override
            public FetchContextLeases leases() {
                return leases;
            }
        };
    }
}
