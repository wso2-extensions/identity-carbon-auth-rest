/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.context.rewrite.valve;

import com.google.gson.JsonObject;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.slf4j.MDC;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.context.rewrite.bean.RewriteContext;
import org.wso2.carbon.identity.context.rewrite.internal.ContextRewriteValveServiceComponentHolder;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.core.util.IdentityCoreConstants.ENABLE_TENANT_QUALIFIED_URLS;
import static org.wso2.carbon.identity.core.util.IdentityCoreConstants.TENANT_NAME_FROM_CONTEXT;

public class TenantContextRewriteValve extends ValveBase {

    private static final String TENANT_DOMAIN = "tenantDomain";
    private static final String TENANT_ID = "tenantId";
    private static final String ORG_MAPPED_TENANT_DOMAIN = "xyz.com";
    private static List<RewriteContext> contextsToRewrite;
    private static List<String> contextListToOverwriteDispatch;
    private static List<String> ignorePathListForOverwriteDispatch;
    private boolean isTenantQualifiedUrlsEnabled;
    private TenantManager tenantManager;

    private static final Log log = LogFactory.getLog(TenantContextRewriteValve.class);

    @Override
    protected synchronized void startInternal() throws LifecycleException {

        super.startInternal();
        // Initialize the tenant context rewrite valve.
        contextsToRewrite = getContextsToRewrite();
        contextListToOverwriteDispatch = getContextListToOverwriteDispatchLocation();
        ignorePathListForOverwriteDispatch = getIgnorePathListForOverwriteDispatch();
        isTenantQualifiedUrlsEnabled = isTenantQualifiedUrlsEnabled();

    }

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {

        String requestURI = request.getRequestURI();
        String contextToForward = null;
        boolean isContextRewrite = false;
        boolean isWebApp = false;
        boolean isOrgUrl = false;

        //Get the rewrite contexts and check whether request URI contains any of rewrite contains.
        for (RewriteContext context : contextsToRewrite) {
            Pattern patternTenant = context.getTenantContextPattern();
            Pattern patternSuperTenant = context.getBaseContextPattern();
            Pattern orgPattern = Pattern.compile("^/t/([^/]+)/o/([^/]+)" + context.getContext());
            if (patternTenant.matcher(requestURI).find() || patternTenant.matcher(requestURI + "/").find()) {
                isContextRewrite = true;
                isWebApp = context.isWebApp();
                contextToForward = context.getContext();
                break;
            } else if (orgPattern.matcher(requestURI).find() || orgPattern.matcher(requestURI + "/").find()) {
                isContextRewrite = true;
                isWebApp = context.isWebApp();
                contextToForward = context.getContext();
                isOrgUrl = true;
                break;
            } else if (isTenantQualifiedUrlsEnabled && (patternSuperTenant.matcher(requestURI).find() ||
                    patternSuperTenant.matcher(requestURI + "/").find())) {
                IdentityUtil.threadLocalProperties.get().put(TENANT_NAME_FROM_CONTEXT, MultitenantConstants
                        .SUPER_TENANT_DOMAIN_NAME);
                break;
            }
        }


        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        try {
            MDC.put(TENANT_DOMAIN, tenantDomain);
            MDC.put(TENANT_ID, String.valueOf(IdentityTenantUtil.getTenantId(tenantDomain)));
            //request URI is not a rewrite one
            if (!isContextRewrite) {
                getNext().invoke(request, response);
                return;
            }
            tenantManager = ContextRewriteValveServiceComponentHolder.getInstance().getRealmService()
                    .getTenantManager();
            if (tenantDomain != null &&
                    !tenantManager.isTenantActive(IdentityTenantUtil.getTenantId(tenantDomain))) {
                handleInvalidTenantDomainErrorResponse(response, HttpServletResponse.SC_NOT_FOUND, tenantDomain);
            } else if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled() && MultitenantConstants
                    .SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
                if (log.isDebugEnabled()) {
                    log.debug("Tenant qualified URL feature is enabled. Hence restricting the access to super tenant" +
                            " domain via /t/carbon.super context. Super tenant should be invoked without the tenant " +
                            "in context path using the server base path.");
                }
                handleRestrictedTenantDomainErrorResponse(request, response);

            } else {
                IdentityUtil.threadLocalProperties.get().put(TENANT_NAME_FROM_CONTEXT, tenantDomain);

/*                if (isWebApp) {
                    String dispatchLocation = "/" + requestURI.replace("/t/" + tenantDomain + contextToForward, "");
                    if (contextListToOverwriteDispatch.contains(contextToForward) && !isIgnorePath(dispatchLocation)) {
                        dispatchLocation = "/";
                    }

                    request.getContext().setCrossContext(true);
                    request.getServletContext().getContext(contextToForward)
                            .getRequestDispatcher(dispatchLocation).forward(request, response);
                }*/
                if (isWebApp) {
                    if (isOrgUrl) {
                        String orgDomain = getOrgDomainFromURLMapping(requestURI);
                        String dispatchLocation = "/" + requestURI.replace("/t/" + tenantDomain + "/o/" + orgDomain +
                                contextToForward, "");
                        try {
                            PrivilegedCarbonContext.startTenantFlow();
                            PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(ORG_MAPPED_TENANT_DOMAIN, true);
                            IdentityUtil.threadLocalProperties.get().put(TENANT_NAME_FROM_CONTEXT, ORG_MAPPED_TENANT_DOMAIN);
                            request.getContext().setCrossContext(true);
                            request.getServletContext().getContext(contextToForward)
                                    .getRequestDispatcher(dispatchLocation).forward(request, response);
                        } finally {
                            PrivilegedCarbonContext.endTenantFlow();
                        }
                    } else {
                        String dispatchLocation = "/" + requestURI.replace("/t/" + tenantDomain + contextToForward, "");
                        if (contextListToOverwriteDispatch.contains(contextToForward) && !isIgnorePath(dispatchLocation)) {
                            dispatchLocation = "/";
                        }
                        request.getContext().setCrossContext(true);
                        request.getServletContext().getContext(contextToForward)
                                .getRequestDispatcher(dispatchLocation).forward(request, response);
                    }
                } else {
                    String carbonWebContext = ServerConfiguration.getInstance().getFirstProperty("WebContextRoot");
                    if (requestURI.contains(carbonWebContext)) {
                        requestURI = requestURI.replace(carbonWebContext + "/", "");
                    }
                    //Servlet
                    requestURI = requestURI.replace("/t/" + tenantDomain, "");
                    request.getRequestDispatcher(requestURI).forward(request, response);
                }
            }
        } catch (UserStoreException ex) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while validating tenant domain.", ex);
            }
            handleInvalidTenantDomainErrorResponse(response, HttpServletResponse.SC_NOT_FOUND, tenantDomain);
        } catch (IdentityRuntimeException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while validating tenant domain.", e);
            }
            String INVALID_TENANT_DOMAIN = "Invalid tenant domain";
            if (!StringUtils.isBlank(e.getMessage()) && e.getMessage().contains(INVALID_TENANT_DOMAIN)) {
                handleInvalidTenantDomainErrorResponse(response, HttpServletResponse.SC_NOT_FOUND, tenantDomain);
            } else {
                handleRuntimeErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, tenantDomain);
            }
        } finally {
            IdentityUtil.threadLocalProperties.get().remove(TENANT_NAME_FROM_CONTEXT);
            MDC.remove(TENANT_DOMAIN);
            MDC.remove(TENANT_ID);
        }
    }

    private String getOrgDomainFromURLMapping(String requestURI) {

        String temp = requestURI.substring(requestURI.indexOf("/o/") + 3);
        int index = temp.indexOf('/');
        if (index != -1) {
            return temp.substring(0, index);
        }
        return temp;
    }

    private boolean isTenantQualifiedUrlsEnabled() {

        Map<String, Object> configuration = IdentityConfigParser.getInstance().getConfiguration();
        String enableTenantQualifiedUrls = (String) configuration.get(ENABLE_TENANT_QUALIFIED_URLS);
        return Boolean.parseBoolean(enableTenantQualifiedUrls);
    }

    private List<RewriteContext> getContextsToRewrite() {
        List<RewriteContext> rewriteContexts = new ArrayList<>();
        Map<String, Object> configuration = IdentityConfigParser.getInstance().getConfiguration();
        Object webAppContexts = configuration.get("TenantContextsToRewrite.WebApp.Context");
        if (webAppContexts != null) {
            if (webAppContexts instanceof ArrayList) {
                for (String context : (ArrayList<String>) webAppContexts) {
                    rewriteContexts.add(new RewriteContext(true, context));
                }
            } else {
                rewriteContexts.add(new RewriteContext(true, webAppContexts.toString()));
            }
        }

        Object servletContexts = configuration.get("TenantContextsToRewrite.Servlet.Context");
        if (servletContexts != null) {
            if (servletContexts instanceof ArrayList) {
                for (String context : (ArrayList<String>) servletContexts) {
                    rewriteContexts.add(new RewriteContext(false, context));
                }
            } else {
                rewriteContexts.add(new RewriteContext(false, servletContexts.toString()));
            }
        }
        return rewriteContexts;
    }

    /**
     * Get context list to overwrite dispatch location.
     *
     * @return list of contexts.
     */
    private List<String> getContextListToOverwriteDispatchLocation() {

        return getConfigValues("TenantContextsToRewrite.OverwriteDispatch.Context");
    }

    /**
     * Get path list to ignore for overwrite dispatch.
     *
     * @return list of paths.
     */
    private List<String> getIgnorePathListForOverwriteDispatch() {

        return getConfigValues("TenantContextsToRewrite.OverwriteDispatch.IgnorePath");
    }

    private List<String> getConfigValues(String elementPath) {

        Map<String, Object> configuration = IdentityConfigParser.getInstance().getConfiguration();
        Object elements = configuration.get(elementPath);
        if (elements != null) {
            List<String> configValues = new ArrayList<>();
            if (elements instanceof List) {
                configValues.addAll((List<String>) elements);
            } else {
                configValues.add(elements.toString());
            }
            return configValues;
        }
        return Collections.emptyList();
    }

    private boolean isIgnorePath(String dispatchLocation) {

        for (String path : ignorePathListForOverwriteDispatch) {
            if (dispatchLocation.startsWith(path)) {
                return true;
            }
        }
        return false;
    }

    private void handleRuntimeErrorResponse(Response response, int error, String tenantDomain) throws
            IOException, ServletException {

        response.setContentType("application/json");
        response.setStatus(error);
        response.setCharacterEncoding("UTF-8");
        JsonObject errorResponse = new JsonObject();
        String errorMsg = "Error occurred while validating tenant domain: " + tenantDomain;
        errorResponse.addProperty("code", error);
        errorResponse.addProperty("message", errorMsg);
        errorResponse.addProperty("description", errorMsg);
        response.getWriter().print(errorResponse.toString());
    }

    private void handleInvalidTenantDomainErrorResponse(Response response, int error, String tenantDomain) throws
            IOException, ServletException {

        response.setContentType("application/json");
        response.setStatus(error);
        response.setCharacterEncoding("UTF-8");
        JsonObject errorResponse = new JsonObject();
        String errorMsg = "invalid tenant domain : " + tenantDomain;
        errorResponse.addProperty("code", error);
        errorResponse.addProperty("message", errorMsg);
        errorResponse.addProperty("description", errorMsg);
        response.getWriter().print(errorResponse.toString());
    }

    private void handleRestrictedTenantDomainErrorResponse(Request request, Response response) throws IOException {

        String requestContentType = request.getContentType();
        if (StringUtils.contains(requestContentType, "application/json")) {
            response.setContentType("application/json");
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setCharacterEncoding("UTF-8");
            JsonObject errorResponse = new JsonObject();
            errorResponse.addProperty("code", HttpServletResponse.SC_FORBIDDEN);
            String errorMsg = "Access to super tenant domain over tenanted URL format (/t/carbon.super) is restricted. "
                    + "Please use the server base path instead.";
            errorResponse.addProperty("message", errorMsg);
            errorResponse.addProperty("description", errorMsg);
            response.getWriter().print(errorResponse.toString());
        } else {
            response.setContentType("text/html");
            String errorPage = ContextRewriteValveServiceComponentHolder.getInstance().getPageNotFoundErrorPage();
            response.getWriter().print(errorPage);
        }
    }
}
