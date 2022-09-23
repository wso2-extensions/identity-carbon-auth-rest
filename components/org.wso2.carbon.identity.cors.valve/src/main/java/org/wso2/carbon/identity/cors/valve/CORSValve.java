/**
 * Copyright (c) 2020, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
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

package org.wso2.carbon.identity.cors.valve;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.cors.mgt.core.exception.CORSManagementServiceException;
import org.wso2.carbon.identity.cors.mgt.core.model.CORSConfiguration;
import org.wso2.carbon.identity.cors.service.CORSManager;
import org.wso2.carbon.identity.cors.valve.exception.CORSException;
import org.wso2.carbon.identity.cors.valve.internal.CORSValveServiceHolder;
import org.wso2.carbon.identity.cors.valve.internal.handler.CORSRequestHandler;
import org.wso2.carbon.identity.cors.valve.internal.util.CORSUtils;
import org.wso2.carbon.identity.cors.valve.internal.util.RequestTagger;
import org.wso2.carbon.identity.cors.valve.model.CORSRequestType;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * Valve class for CORS.
 */
public class CORSValve extends ValveBase {

    private static final Log log = LogFactory.getLog(CORSValve.class);

    private final CORSRequestHandler corsRequestHandler;

    /**
     * Default constructor for the CORSValve.
     */
    public CORSValve() {

        corsRequestHandler = new CORSRequestHandler();
    }

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {

        // Determine the type of the request.
        CORSRequestType corsRequestType = CORSUtils.getRequestType(request);
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();

        try {
            // Tag if configured.
            CORSManager corsManager = CORSValveServiceHolder.getInstance().getCorsManager();
            CORSConfiguration corsConfiguration = corsManager.getCORSConfiguration(tenantDomain);
            if (corsConfiguration.isTagRequests()) {
                RequestTagger.tag(request, corsRequestType);
            }

            if (corsRequestType == CORSRequestType.SIMPLE || corsRequestType == CORSRequestType.ACTUAL) {
                // Simple and Actual requests are handled in a same way.
                corsRequestHandler.handleActualRequest(request, response);
                getNext().invoke(request, response);
            } else if (corsRequestType == CORSRequestType.PREFLIGHT) {
                // Preflight requests - Handle but don't pass further down the chain.
                corsRequestHandler.handlePreflightRequest(request, response);
            } else {
                // Not CORS requests.
                getNext().invoke(request, response);
            }
        } catch (CORSException e) {
            printMessage(e, response);
        } catch (CORSManagementServiceException e) {
            log.error("CORS management service error when intercepting an HTTP request.", e);
            response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        }
    }

    /**
     * Produces a simple HTTP text/plain response for the specified CORS
     * exception.
     * Note: The CORS filter avoids falling back to the default web container error page (typically a
     * richly-formatted HTML page) to make it easier for XHR debugger tools to identify the cause of failed requests.
     *
     * @param e        The CORS exception. Must not be {@code null}.
     * @param response The HTTP servlet response. Must not be {@code null}.
     * @throws IOException On a I/O exception.
     */
    private void printMessage(final CORSException e, final HttpServletResponse response) throws IOException {

        // Set the status code.
        response.setStatus(e.getHttpStatusCode());

        // Write the error message.
        response.resetBuffer();
        response.setContentType("text/plain");
        PrintWriter out = response.getWriter();
        out.println("CORS Valve: " + e.getMessage());

        if (log.isDebugEnabled()) {
            log.debug("CORS valve error when intercepting an HTTP request.", e);
        }
    }
}
