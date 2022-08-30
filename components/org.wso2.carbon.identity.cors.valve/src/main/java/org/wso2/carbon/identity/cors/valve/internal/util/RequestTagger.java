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

/**
 * Request tagger. Tags HTTP servlet requests to provide CORS information to downstream handlers.
 */
public final class RequestTagger {

    /**
     * Private constructor of RequestTagger.
     */
    private RequestTagger() {

    }

    /**
     * Tags an HTTP servlet request to provide CORS information to downstream handlers.
     * Tagging is provided via {@code HttpServletRequest.setAttribute()}.
     * {@code cors.isCorsRequest} set to {@code true} or {@code false}.
     * {@code cors.origin} set to the value of the "Origin" header, {@code null} if undefined.
     * {@code cors.requestType} set to "actual" or "preflight" (for CORS requests).
     * {@code cors.requestHeaders} set to the value of the "Access-Control-Request-Headers" or {@code null} if
     * undefined (added for preflight CORS requests only).
     *
     * @param request The servlet request to inspect and tag. Must not be {@code null}.
     * @param type    The detected request type. Must not be {@code null}.
     */
    public static void tag(final HttpServletRequest request, final CORSRequestType type) {

        switch (type) {
            case ACTUAL:
                request.setAttribute("cors.isCorsRequest", true);
                request.setAttribute("cors.origin", request.getHeader(Header.ORIGIN));
                request.setAttribute("cors.requestType", "actual");
                break;
            case PREFLIGHT:
                request.setAttribute("cors.isCorsRequest", true);
                request.setAttribute("cors.origin", request.getHeader(Header.ORIGIN));
                request.setAttribute("cors.requestType", "preflight");
                request.setAttribute("cors.requestHeaders", request.getHeader(Header.ACCESS_CONTROL_REQUEST_HEADERS));
                break;
            case NOT_CORS:
                request.setAttribute("cors.isCorsRequest", false);
        }
    }
}
