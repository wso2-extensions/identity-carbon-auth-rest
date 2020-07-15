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
 */

package org.wso2.carbon.identity.custom.header.filter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.configuration.mgt.core.exception.ConfigurationManagementException;
import org.wso2.carbon.identity.configuration.mgt.core.model.Resource;
import org.wso2.carbon.identity.custom.header.filter.function.ResourceToCustomHeader;
import org.wso2.carbon.identity.custom.header.filter.internal.CustomHeaderDataHolder;
import org.wso2.carbon.identity.custom.header.filter.model.Header;

import java.io.IOException;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

/**
 * Custom Header Filter.
 */
public class CustomHeaderFilter implements Filter {

    private static final Log log = LogFactory.getLog(CustomHeaderFilter.class);
    private static final String RESOURCE_TYPE = "custom-headers";

    @Override
    public void init(FilterConfig filterConfig) {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        // Add custom headers that is configured as resources in the resource management service.
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        String applicationName = PrivilegedCarbonContext.getThreadLocalCarbonContext().getApplicationName();

        // Application name will be null for the management console. We can safely ignore that.
        if (applicationName != null) {
            try {
                // Resource type should be created as "custom-headers". Only those will be read.
                Resource resource = CustomHeaderDataHolder.getInstance().getConfigurationManager()
                        .getResource(RESOURCE_TYPE, applicationName);
                // Convert resource to headers. There can be multiple headers in the resource.
                List<Header> headerList = new ResourceToCustomHeader().apply(resource);
                for (Header header : headerList) {
                    // Apply those headers to the response.
                    httpResponse.addHeader(header.getName(), header.getValue());
                }
            } catch (ConfigurationManagementException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Cannot add custom header for application: " + applicationName, e);
                }
            } catch (Exception e) {
                // If an error occurred, we have to continue without breaking the flow.
                log.error("Error in adding custom header", e);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Application name not found to add custom header");
            }
        }
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
    }
}
