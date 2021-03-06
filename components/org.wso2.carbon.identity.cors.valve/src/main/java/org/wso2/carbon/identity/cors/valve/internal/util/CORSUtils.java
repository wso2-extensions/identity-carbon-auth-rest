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

package org.wso2.carbon.identity.cors.valve.internal.util;

import org.wso2.carbon.identity.cors.valve.constant.Header;
import org.wso2.carbon.identity.cors.valve.constant.RequestMethod;
import org.wso2.carbon.identity.cors.valve.model.CORSRequestType;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;

/**
 * A utility class for CORS operations.
 */
public class CORSUtils {

    private static final Collection<String> SIMPLE_HTTP_REQUEST_CONTENT_TYPE_VALUES =
            Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
                    "application/x-www-form-urlencoded", "multipart/form-data", "text/plain")));

    /**
     * Private constructor of CORSUtils.
     */
    private CORSUtils() {

    }

    /**
     * Decide whether a particular request belongs to {@code SIMPLE}, {@code PREFLIGHT} or {@code CORS} type.
     *
     * @param request Request to be checked
     * @return {@code SIMPLE}, {@code PREFLIGHT} or {@code CORS} depending on the type of the {@code request}.
     */
    public static CORSRequestType getRequestType(HttpServletRequest request) {

        String serverOrigin = request.getScheme() + "://" + request.getHeader(Header.HOST);
        String method = request.getMethod();
        String mediaType = HeaderUtils.getMediaType(request.getContentType());
        if (request.getHeader(Header.ORIGIN) == null ||
                (request.getHeader(Header.HOST) != null && request.getHeader(Header.ORIGIN).equals(serverOrigin)) ||
                ("POST".equals(method) && SIMPLE_HTTP_REQUEST_CONTENT_TYPE_VALUES.contains(mediaType))) {
            // Condition I   - A request without the Origin header is never a CORS nor Preflight request.
            // Condition II  - Requests that have Origin header but submitted for the same domain.
            // Condition III - A request with a simple HTTP Post Request content type value.
            return CORSRequestType.OTHER;
        } else if (request.getHeader(Header.ACCESS_CONTROL_REQUEST_METHOD) != null &&
                request.getMethod() != null &&
                request.getMethod().equalsIgnoreCase(RequestMethod.OPTIONS)) {
            return CORSRequestType.PREFLIGHT;
        } else {
            return CORSRequestType.ACTUAL;
        }
    }
}
