/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 * NOTE: The code/logic in this class is copied from https://bitbucket.org/thetransactioncompany/cors-filter.
 * All credits goes to the original authors of the project https://bitbucket.org/thetransactioncompany/cors-filter.
 */

package org.wso2.carbon.identity.cors.valve.internal.wrapper;

import org.wso2.carbon.identity.cors.valve.constant.Header;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

/**
 * A response wrapper that preserves the CORS response headers on
 * {@link javax.servlet.ServletResponse#reset()}. Some web applications and
 * frameworks (e.g. RestEasy) reset the servlet response when a HTTP 4xx error
 * is produced; this wrapper ensures previously set CORS headers survive such a
 * reset.
 */
public class CORSResponseWrapper extends HttpServletResponseWrapper {

    /**
     * The names of the CORS response headers to preserve.
     */
    public static final Set<String> RESPONSE_HEADER_NAMES;

    static {
        Set<String> headerNames = new HashSet<>();
        headerNames.add(Header.ACCESS_CONTROL_ALLOW_HEADERS);
        headerNames.add(Header.ACCESS_CONTROL_ALLOW_METHODS);
        headerNames.add(Header.ACCESS_CONTROL_ALLOW_ORIGIN);
        headerNames.add(Header.ACCESS_CONTROL_ALLOW_CREDENTIALS);
        headerNames.add(Header.ACCESS_CONTROL_EXPOSE_HEADERS);
        headerNames.add(Header.ACCESS_CONTROL_MAX_AGE);
        headerNames.add(Header.VARY);
        RESPONSE_HEADER_NAMES = Collections.unmodifiableSet(headerNames);
    }

    /**
     * Creates a new CORS response wrapper for the specified HTTP servlet
     * response.
     *
     * @param response The HTTP servlet response.
     */
    public CORSResponseWrapper(final HttpServletResponse response) {

        super(response);
    }

    @Override
    public void reset() {

        Map<String, String> corsHeaders = new HashMap<>();
        for (String headerName : getHeaderNames()) {
            if (RESPONSE_HEADER_NAMES.contains(headerName)) {
                corsHeaders.put(headerName, getHeader(headerName));
            }
        }

        super.reset();

        for (String headerName : corsHeaders.keySet()) {
            setHeader(headerName, corsHeaders.get(headerName));
        }
    }
}
