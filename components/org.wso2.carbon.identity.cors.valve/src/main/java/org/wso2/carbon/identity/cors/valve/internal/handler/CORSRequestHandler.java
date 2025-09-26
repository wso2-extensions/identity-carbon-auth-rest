/*
 * Copyright (c) 2020-2025, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.carbon.identity.cors.valve.internal.handler;

import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.cors.mgt.core.exception.CORSManagementServiceException;
import org.wso2.carbon.identity.cors.mgt.core.model.CORSConfiguration;
import org.wso2.carbon.identity.cors.mgt.core.model.Origin;
import org.wso2.carbon.identity.cors.service.CORSManager;
import org.wso2.carbon.identity.cors.valve.constant.ErrorMessages;
import org.wso2.carbon.identity.cors.valve.constant.Header;
import org.wso2.carbon.identity.cors.valve.exception.CORSException;
import org.wso2.carbon.identity.cors.valve.internal.CORSValveServiceHolder;
import org.wso2.carbon.identity.cors.valve.internal.util.HeaderUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Request handler for the CORS valve.
 */
public class CORSRequestHandler {

    /**
     * Get CORSManager instance.
     *
     * @return CORSManager
     */
    private CORSManager getCORSManager() {

        return CORSValveServiceHolder.getInstance().getCorsManager();
    }

    /**
     * Handles a simple or actual CORS request.
     *
     * @param request  The HTTP request.
     * @param response The HTTP response.
     * @throws CORSException
     * @throws CORSManagementServiceException
     */
    public void handleActualRequest(HttpServletRequest request, HttpServletResponse response)
            throws CORSException, CORSManagementServiceException {

        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        CORSConfiguration config = getCORSManager().getCORSConfiguration(tenantDomain);
        addStandardHeaders(request, response, config);
    }

    private void addStandardHeaders(HttpServletRequest request, HttpServletResponse response, CORSConfiguration config)
            throws CORSManagementServiceException {

        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        Origin requestOrigin = new Origin(request.getHeader(Header.ORIGIN));

        // Add a single Access-Control-Allow-Origin header.
        if (config.isAllowAnyOrigin() && !config.isSupportsCredentials()) {
            // If any origin is allowed, return header with '*'.
            response.addHeader(Header.ACCESS_CONTROL_ALLOW_ORIGIN, "*");
        } else {
            // Add a single Access-Control-Allow-Origin header, with the value
            // of the Origin header as value.
            if (isAllowedOrigin(tenantDomain, requestOrigin)) {
                response.addHeader(Header.ACCESS_CONTROL_ALLOW_ORIGIN, requestOrigin.toString());
            }
            // If only specific origins are allowed, the response will vary by origin
            response.addHeader(Header.VARY, "Origin");
        }

        // If the resource supports credentials, add a single
        // Access-Control-Allow-Credentials header with the case-sensitive
        // string "true" as value.
        if (config.isSupportsCredentials()) {
            response.addHeader(Header.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
        }

        // If the list of exposed headers is not empty add one or more
        // Access-Control-Expose-Headers headers, with as values the header
        // field names given in the list of exposed headers.
        if (!config.getExposedHeaders().isEmpty()) {
            String exposedHeaders = HeaderUtils.serialize(config.getExposedHeaders(), ", ");
            response.addHeader(Header.ACCESS_CONTROL_EXPOSE_HEADERS, exposedHeaders);
        }
    }

    /**
     * Handles a preflight CORS request.
     *
     * @param request  The HTTP request.
     * @param response The HTTP response.
     * @throws CORSException
     * @throws CORSManagementServiceException
     */
    public void handlePreflightRequest(HttpServletRequest request, HttpServletResponse response) throws
            CORSManagementServiceException, CORSException {

        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        CORSConfiguration config = getCORSManager().getCORSConfiguration(tenantDomain);

        // Check origin against allow list
        Origin requestOrigin = new Origin(request.getHeader(Header.ORIGIN));
        if (!isAllowedOrigin(tenantDomain, requestOrigin)) {
            throw new CORSException(ErrorMessages.ERROR_CODE_ORIGIN_DENIED);
        }

        // Parse requested method
        // Note: method checking must be done after header parsing, see CORS spec.
        String requestMethodHeader = request.getHeader(Header.ACCESS_CONTROL_REQUEST_METHOD);
        if (requestMethodHeader == null) {
            throw new CORSException(ErrorMessages.ERROR_CODE_MISSING_ACCESS_CONTROL_REQUEST_METHOD_HEADER);
        }
        final String requestedMethod = requestMethodHeader.toUpperCase();

        // Parse the requested author (custom) headers
        final String rawRequestHeadersString = request.getHeader(Header.ACCESS_CONTROL_REQUEST_HEADERS);
        final String[] requestHeaderValues = HeaderUtils.parseMultipleHeaderValues(rawRequestHeadersString);
        final String[] requestHeaders = new String[requestHeaderValues.length];

        for (int i = 0; i < requestHeaders.length; i++) {
            try {
                requestHeaders[i] = HeaderUtils.formatCanonical(requestHeaderValues[i]);
            } catch (IllegalArgumentException e) {
                // Invalid header name.
                throw new CORSException(ErrorMessages.ERROR_CODE_INVALID_HEADER_VALUE, e);
            }
        }

        // Check method.
        if (!isSupportedMethod(config, requestedMethod)) {
            throw new CORSException(ErrorMessages.ERROR_CODE_UNSUPPORTED_METHOD);
        }

        // Author request headers check.
        if (!config.isSupportAnyHeader()) {
            for (String requestHeader : requestHeaders) {
                if (!config.getSupportedHeaders().contains(requestHeader)) {
                    throw new CORSException(ErrorMessages.ERROR_CODE_UNSUPPORTED_REQUEST_HEADER);
                }
            }
        }

        // Success, append response headers.
        if (config.isSupportsCredentials()) {
            response.addHeader(Header.ACCESS_CONTROL_ALLOW_ORIGIN, requestOrigin.toString());
            response.addHeader(Header.ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");

            // See https://bitbucket.org/thetransactioncompany/cors-filter/issue/16/.
            response.addHeader(Header.VARY, "Origin");
        } else {
            if (config.isAllowAnyOrigin()) {
                response.addHeader(Header.ACCESS_CONTROL_ALLOW_ORIGIN, "*");
            } else {
                response.addHeader(Header.ACCESS_CONTROL_ALLOW_ORIGIN, requestOrigin.toString());

                // See https://bitbucket.org/thetransactioncompany/cors-filter/issue/16/.
                response.addHeader(Header.VARY, "Origin");
            }
        }

        if (config.getMaxAge() > 0) {
            response.addHeader(Header.ACCESS_CONTROL_MAX_AGE, Integer.toString(config.getMaxAge()));
        }

        String supportedMethods = HeaderUtils.serialize(config.getSupportedMethods(), ", ");
        response.addHeader(Header.ACCESS_CONTROL_ALLOW_METHODS, supportedMethods);

        String supportedHeaders = HeaderUtils.serialize(config.getSupportedHeaders(), ", ");
        if (config.isSupportAnyHeader() && rawRequestHeadersString != null) {
            // Echo author headers.
            response.addHeader(Header.ACCESS_CONTROL_ALLOW_HEADERS, rawRequestHeadersString);
        } else if (!supportedHeaders.isEmpty()) {
            response.addHeader(Header.ACCESS_CONTROL_ALLOW_HEADERS, supportedHeaders);
        }
    }

    /**
     * Check whether requests from the specified origin must be allowed.
     *
     * @param origin The origin as reported by the web client (browser), {@code null} if unknown.
     * @return {@code true} if the origin is allowed, else {@code false}.
     */
    private boolean isAllowedOrigin(final String tenantDomain, final Origin origin)
            throws CORSManagementServiceException {

        // Return true without checking if allowAnyOrigin is set to true.
        if (getCORSManager().getCORSConfiguration(tenantDomain).isAllowAnyOrigin()) {
            return true;
        }

        if (origin == null) {
            return false;
        }

        Origin[] origins = getCORSManager().getCORSOrigins(tenantDomain);
        for (Origin o : origins) {
            String allowedOrigin = o.getValue();
            if (allowedOrigin.endsWith("/")) {
                allowedOrigin = allowedOrigin.substring(0, allowedOrigin.length() - 1);
            }
            if (allowedOrigin.equals(origin.toString())) {
                return true;
            }
        }

        if (getCORSManager().getCORSConfiguration(tenantDomain).isAllowSubdomains()) {
            return isAllowedSubdomainOrigin(tenantDomain, origin);
        }

        return false;
    }

    /**
     * Check whether the specified HTTP method is supported.
     *
     * @param config The CORS configuration.
     * @param method The HTTP method.
     * @return {@code true} if the method is supported, else {@code false}.
     */
    private boolean isSupportedMethod(final CORSConfiguration config, final String method) {

        return config.getSupportedMethods().contains(method);
    }

    /**
     * Check whether the specified origin is a subdomain origin of the allowed origins. This is done by matching the
     * origin's scheme, hostname and port against each of the allowed origins.
     *
     * @param origin The origin as reported by the web client (browser), {@code null} if unknown.
     * @return {@code true} if the origin is an allowed subdomain origin, else {@code false}.
     * @throws CORSManagementServiceException
     */
    private boolean isAllowedSubdomainOrigin(final String tenantDomain, final Origin origin)
            throws CORSManagementServiceException {

        for (Origin o : getCORSManager().getCORSOrigins(tenantDomain)) {
            if (origin.getSuffix().endsWith("." + o.getSuffix())
                    && origin.getScheme().equalsIgnoreCase(o.getScheme())) {
                return true;
            }
        }

        return false;
    }
}
