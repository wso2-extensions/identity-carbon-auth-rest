/**
 * Copyright (c) 2022, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.cors.valve.internal.util;

import org.wso2.carbon.identity.cors.valve.constant.Header;

import org.wso2.carbon.identity.cors.valve.model.CORSRequestType;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;

import static org.wso2.carbon.identity.cors.valve.constant.RequestMethod.GET;
import static org.wso2.carbon.identity.cors.valve.constant.RequestMethod.HEAD;
import static org.wso2.carbon.identity.cors.valve.constant.RequestMethod.OPTIONS;
import static org.wso2.carbon.identity.cors.valve.constant.RequestMethod.POST;

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
                (request.getHeader(Header.HOST) != null && request.getHeader(Header.ORIGIN).equals(serverOrigin))) {
            // Condition I   - A request without the Origin header is never a CORS nor Preflight request.
            // Condition II  - Requests that have Origin header but submitted for the same domain.
            return CORSRequestType.NOT_CORS;
        } else if (GET.equals(method) || HEAD.equals(method) ||
                (POST.equals(method) && SIMPLE_HTTP_REQUEST_CONTENT_TYPE_VALUES.contains(mediaType))) {
            return CORSRequestType.SIMPLE;
        } else if (request.getHeader(Header.ACCESS_CONTROL_REQUEST_METHOD) != null &&
                OPTIONS.equals(method)) {
            return CORSRequestType.PREFLIGHT;
        } else {
            return CORSRequestType.ACTUAL;
        }
    }
}
