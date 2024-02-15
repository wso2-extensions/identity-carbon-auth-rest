/*
 * Copyright (c) 2022-2023, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.context.rewrite.valve;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.MDC;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.context.rewrite.bean.OrganizationRewriteContext;
import org.wso2.carbon.identity.context.rewrite.internal.ContextRewriteValveServiceComponentHolder;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.context.rewrite.constant.RewriteConstants.ORGANIZATION_PATH_PARAM;
import static org.wso2.carbon.identity.context.rewrite.constant.RewriteConstants.TENANT_DOMAIN;
import static org.wso2.carbon.identity.context.rewrite.constant.RewriteConstants.TENANT_ID;
import static org.wso2.carbon.identity.context.rewrite.util.Utils.getOrganizationDomainFromURL;
import static org.wso2.carbon.identity.context.rewrite.util.Utils.handleErrorResponse;
import static org.wso2.carbon.identity.context.rewrite.util.Utils.isAccessingOrganizationUnderSuperTenant;
import static org.wso2.carbon.identity.core.util.IdentityCoreConstants.TENANT_NAME_FROM_CONTEXT;

/**
 * Rewrite organization specific routing supported paths.
 */
public class OrganizationContextRewriteValve extends ValveBase {


    @Override
    protected synchronized void startInternal() throws LifecycleException {

        super.startInternal();
    }

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {

        String requestURI = request.getRequestURI();
        String contextToForward = null;
        boolean orgRoutingPathSupported = false;
        boolean orgRoutingSubPathSupported = false;
        boolean subPathsConfigured = false;
        boolean isWebApp = false;

        /* Organization context rewrite valve can be skipped when accessing organization under the super tenant.
           Ex - /o/api/server/v1/applications */
        if (isAccessingOrganizationUnderSuperTenant()) {
            getNext().invoke(request, response);
            return;
        }

        if (ContextRewriteValveServiceComponentHolder.getInstance().isOrganizationManagementEnabled() &&
                StringUtils.startsWith(requestURI, ORGANIZATION_PATH_PARAM)) {
            for (OrganizationRewriteContext organizationRewriteContext
                    : ContextRewriteValveServiceComponentHolder.getInstance().getOrganizationRewriteContexts()) {
                Pattern orgPattern = organizationRewriteContext.getOrgContextPattern();
                if (orgPattern.matcher(requestURI).find() || orgPattern.matcher(requestURI + "/").find()) {
                    subPathsConfigured = false;
                    orgRoutingPathSupported = true;
                    isWebApp = organizationRewriteContext.isWebApp();
                    contextToForward = organizationRewriteContext.getContext();

                    if (CollectionUtils.isNotEmpty(organizationRewriteContext.getSubPaths())) {
                        subPathsConfigured = true;
                        for (Pattern subPath : organizationRewriteContext.getSubPaths()) {
                            if (subPath.matcher(requestURI).find() || subPath.matcher(requestURI + "/").find()) {
                                orgRoutingSubPathSupported = true;
                                break;
                            }
                        }
                    }

                    if (orgRoutingSubPathSupported || !subPathsConfigured) {
                        break;
                    }
                }
            }

            /*
            There is a possibility for the request URI to match with multiple configured base path patterns.
            Hence, we need to ensure that an error response is displayed only if the request URI doesn't match any of
            the base paths and any sub paths that might be defined under them.
             */
            if (!orgRoutingPathSupported || (subPathsConfigured && !orgRoutingSubPathSupported)) {
                handleErrorResponse(HttpServletResponse.SC_NOT_FOUND, "Organization specific routing failed.",
                        "Unsupported organization specific routing endpoint.", response);
                return;
            }
        } else {
            getNext().invoke(request, response);
            return;
        }

        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        try {
            MDC.put(TENANT_DOMAIN, tenantDomain);
            MDC.put(TENANT_ID, String.valueOf(IdentityTenantUtil.getTenantId(tenantDomain)));

            IdentityUtil.threadLocalProperties.get().put(TENANT_NAME_FROM_CONTEXT, tenantDomain);

            String orgDomain = getOrganizationDomainFromURL(requestURI);
            if (isWebApp) {
                String dispatchLocation = "/" + requestURI.replace(ORGANIZATION_PATH_PARAM + orgDomain +
                        contextToForward, StringUtils.EMPTY);
                request.getContext().setCrossContext(true);
                request.getServletContext().getContext(contextToForward)
                        .getRequestDispatcher(dispatchLocation).forward(request, response);
            } else {
                String carbonWebContext = ServerConfiguration.getInstance().getFirstProperty("WebContextRoot");
                if (requestURI.contains(carbonWebContext)) {
                    requestURI = requestURI.replace(carbonWebContext + "/", "");
                }
                //Servlet
                requestURI = requestURI.replace(ORGANIZATION_PATH_PARAM + orgDomain, StringUtils.EMPTY);
                request.getRequestDispatcher(requestURI).forward(request, response);
            }
        } finally {
            IdentityUtil.threadLocalProperties.get().remove(TENANT_NAME_FROM_CONTEXT);
            unsetMDCThreadLocals();
        }
    }

    private void unsetMDCThreadLocals() {

        MDC.remove(TENANT_DOMAIN);
        MDC.remove(TENANT_ID);
    }
}
