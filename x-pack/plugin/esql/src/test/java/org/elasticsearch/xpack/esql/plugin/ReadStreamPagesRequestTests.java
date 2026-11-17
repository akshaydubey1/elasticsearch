/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

package org.elasticsearch.xpack.esql.plugin;

import org.elasticsearch.core.TimeValue;
import org.elasticsearch.test.ESTestCase;
import org.elasticsearch.xpack.esql.plugin.TransportReadStreamPagesAction.Request;

import static org.elasticsearch.xpack.esql.plugin.TransportReadStreamPagesAction.MAX_PAGES_PER_READ;
import static org.elasticsearch.xpack.esql.plugin.TransportReadStreamPagesAction.MAX_WAIT_TIMEOUT;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.nullValue;

public class ReadStreamPagesRequestTests extends ESTestCase {

    public void testValid() {
        assertThat(new Request("r", 0, MAX_PAGES_PER_READ, 0, MAX_WAIT_TIMEOUT).validate(), nullValue());
        assertThat(Request.fromRow("r", 0, 1, Long.MAX_VALUE, TimeValue.ZERO).validate(), nullValue());
    }

    public void testInvalid() {
        assertInvalid(new Request("r", -1, 1, 0, TimeValue.ZERO), "[fromSeq] or [fromRow]");
        assertInvalid(new Request("r", 1, 0, 0, TimeValue.ZERO), "[maxPages]");
        assertInvalid(new Request("r", 1, MAX_PAGES_PER_READ + 1, 0, TimeValue.ZERO), "[maxPages]");
        assertInvalid(new Request("r", 1, 1, -1, TimeValue.ZERO), "[maxBytes]");
        assertInvalid(new Request("r", 1, 1, 0, TimeValue.timeValueMillis(MAX_WAIT_TIMEOUT.millis() + 1)), "[waitTimeout]");
    }

    private static void assertInvalid(Request request, String message) {
        assertThat(request.validate().getMessage(), containsString(message));
    }
}
