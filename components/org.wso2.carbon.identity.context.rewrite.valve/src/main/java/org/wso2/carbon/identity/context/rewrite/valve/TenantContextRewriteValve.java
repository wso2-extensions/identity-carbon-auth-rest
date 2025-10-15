/*
 * Copyright (c) 2016-2023, WSO2 LLC. (http://www.wso2.com).
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

import com.google.gson.JsonObject;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.slf4j.MDC;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.context.rewrite.bean.OrganizationRewriteContext;
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
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.context.rewrite.constant.RewriteConstants.ORGANIZATION_PATH_PARAM;
import static org.wso2.carbon.identity.context.rewrite.constant.RewriteConstants.SUPER_TENANT_QUALIFIED_REQUEST;
import static org.wso2.carbon.identity.context.rewrite.constant.RewriteConstants.TENANT_DOMAIN;
import static org.wso2.carbon.identity.context.rewrite.constant.RewriteConstants.TENANT_ID;
import static org.wso2.carbon.identity.context.rewrite.util.Utils.isAccessingOrganizationUnderSuperTenant;
import static org.wso2.carbon.identity.core.util.IdentityCoreConstants.ENABLE_TENANT_QUALIFIED_URLS;
import static org.wso2.carbon.identity.core.util.IdentityCoreConstants.TENANT_NAME_FROM_CONTEXT;

public class TenantContextRewriteValve extends ValveBase {

    private static List<RewriteContext> contextsToRewrite;
    private static List<OrganizationRewriteContext> contextsToRewriteInTenantPerspective;
    private static List<String> contextListToOverwriteDispatch;
    private static List<String> ignorePathListForOverwriteDispatch;
    private static List<String> organizationRoutingOnlySupportedAPIPaths;
    private boolean isTenantQualifiedUrlsEnabled;
    private TenantManager tenantManager;

    private static final Log log = LogFactory.getLog(TenantContextRewriteValve.class);

    @Override
    protected synchronized void startInternal() throws LifecycleException {

        super.startInternal();
        // Initialize the tenant context rewrite valve.
        contextsToRewrite = getContextsToRewrite();
        contextsToRewriteInTenantPerspective = getContextsToRewriteInTenantPerspective();
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

        /* If an organization under the super tenant is accessed with organization qualified URL, it is prefixed
           with super tenant domain qualifier. /o/... -> /t/<carbon.super>/o/... */
        if (StringUtils.startsWith(requestURI, ORGANIZATION_PATH_PARAM) && isAccessingOrganizationUnderSuperTenant()) {
            requestURI = requestURI.replace(ORGANIZATION_PATH_PARAM, SUPER_TENANT_QUALIFIED_REQUEST);
        }

        String contextTenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        //Get the rewrite contexts and check whether request URI contains any of rewrite contains.
        for (RewriteContext context : contextsToRewrite) {
            Pattern patternTenant = context.getTenantContextPattern();
            Pattern patternSuperTenant = context.getBaseContextPattern();
            if (patternTenant.matcher(requestURI).find() || patternTenant.matcher(requestURI + "/").find()) {
                isContextRewrite = true;
                isWebApp = context.isWebApp();
                contextToForward = context.getContext();
                break;
            } else if (isTenantQualifiedUrlsEnabled && (patternSuperTenant.matcher(requestURI).find() ||
                    patternSuperTenant.matcher(requestURI + "/").find())) {
                IdentityUtil.threadLocalProperties.get().put(TENANT_NAME_FROM_CONTEXT, contextTenantDomain);
                break;
            }
        }

        outerLoop:
        for (OrganizationRewriteContext context : contextsToRewriteInTenantPerspective) {
            Pattern patternTenantPerspective = Pattern.compile("^/t/[^/]+/o/[a-f0-9\\-]+?" + context.getContext());
            if (patternTenantPerspective.matcher(requestURI).find()) {
                if (CollectionUtils.isEmpty(context.getSubPaths())) {
                    isContextRewrite = true;
                    isWebApp = context.isWebApp();
                    contextToForward = context.getContext();
                    int startIndex = requestURI.indexOf("/o/") + 3;
                    int endIndex = requestURI.indexOf("/", startIndex);
                    String appOrgId = requestURI.substring(startIndex, endIndex);
                    PrivilegedCarbonContext.getThreadLocalCarbonContext()
                            .setApplicationResidentOrganizationId(appOrgId);
                    break;
                }
                for (Pattern subPath : context.getSubPaths()) {
                    if (subPath.matcher(requestURI).find()) {
                        isContextRewrite = true;
                        isWebApp = context.isWebApp();
                        contextToForward = context.getContext();
                        int startIndex = requestURI.indexOf("/o/") + 3;
                        int endIndex = requestURI.indexOf("/", startIndex);
                        String appOrgId = requestURI.substring(startIndex, endIndex);
                        PrivilegedCarbonContext.getThreadLocalCarbonContext().
                                setApplicationResidentOrganizationId(appOrgId);
                        break outerLoop;
                    }
                }
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
            } else {
                IdentityUtil.threadLocalProperties.get().put(TENANT_NAME_FROM_CONTEXT, tenantDomain);

                if (isWebApp) {
                    String dispatchLocation = "/" + requestURI.replaceAll("/t/.*" + contextToForward, "");
                    /* Verify the request not start with /o/ for backward compatibility. If /o/ path is found middle of
                     the request it should be dispatched to organization APIs.
                     Ex-: Request: /t/<tenant-domain>/o/api/server/v1/applications  -->  /o/server/v1/applications
                     */
                    if (!requestURI.startsWith(ORGANIZATION_PATH_PARAM) &&
                            requestURI.contains(ORGANIZATION_PATH_PARAM) &&
                            !isOrganizationIdAvailableInTenantPerspective(requestURI)) {
                        dispatchLocation = "/o" + dispatchLocation;
                    }
                    if (contextListToOverwriteDispatch.contains(contextToForward) && !isIgnorePath(dispatchLocation)) {
                        dispatchLocation = "/";
                    }

                    request.getContext().setCrossContext(true);
                    request.getServletContext().getContext(contextToForward)
                            .getRequestDispatcher(dispatchLocation).forward(request, response);
                } else {
                    String carbonWebContext = ServerConfiguration.getInstance().getFirstProperty("WebContextRoot");
                    if (requestURI.contains(carbonWebContext)) {
                        requestURI = requestURI.replace(carbonWebContext + "/", "");
                    }
                    //Servlet
                    if (StringUtils.isEmpty(PrivilegedCarbonContext.getThreadLocalCarbonContext()
                            .getApplicationResidentOrganizationId())) {
                        requestURI = requestURI.replace("/t/" + tenantDomain, "");
                    }
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
            unsetMDCThreadLocals();
        }
    }

    private void unsetMDCThreadLocals() {

        MDC.remove(TENANT_DOMAIN);
        MDC.remove(TENANT_ID);
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

    private List<OrganizationRewriteContext> getContextsToRewriteInTenantPerspective() {

        List<OrganizationRewriteContext> organizationRewriteContexts = new ArrayList<>();
        Map<String, Object> configuration = IdentityConfigParser.getInstance().getConfiguration();
        Object webAppBasePathContexts = configuration.get("OrgContextsToRewriteInTenantPerspective.WebApp.Context." +
                "BasePath");
        setOrganizationRewriteContexts(organizationRewriteContexts, webAppBasePathContexts, true);

        Object webAppSubPathContexts = configuration.get("OrgContextsToRewriteInTenantPerspective.WebApp.Context." +
                "SubPaths.Path");
        setSubPathContexts(organizationRewriteContexts, webAppSubPathContexts);

        // Add Servlet context support for tenant perspective.
        Object servletBasePathContexts = configuration.get("OrgContextsToRewriteInTenantPerspective.Servlet.Context");
        setOrganizationRewriteContexts(organizationRewriteContexts, servletBasePathContexts, false);

        return organizationRewriteContexts;
    }

    private void setOrganizationRewriteContexts(List<OrganizationRewriteContext> organizationRewriteContexts,
                                                Object basePathContexts, boolean isWebApp) {

        if (basePathContexts != null) {
            if (basePathContexts instanceof ArrayList) {
                for (String context : (ArrayList<String>) basePathContexts) {
                    organizationRewriteContexts.add(new OrganizationRewriteContext(isWebApp, context));
                }
            } else {
                organizationRewriteContexts.add(new OrganizationRewriteContext(isWebApp,
                        basePathContexts.toString()));
            }
        }
    }

    private void setSubPathContexts(List<OrganizationRewriteContext> organizationRewriteContexts,
                                    Object subPathContexts) {

        if (subPathContexts instanceof ArrayList) {
            for (String subPath : (ArrayList<String>) subPathContexts) {
                Optional<OrganizationRewriteContext> maybeOrgRewriteContext = organizationRewriteContexts.stream()
                        .filter(rewriteContext -> subPath.startsWith(rewriteContext.getContext()))
                        .max(Comparator.comparingInt(rewriteContext -> rewriteContext.getContext().length()));
                maybeOrgRewriteContext.ifPresent(
                        organizationRewriteContext -> organizationRewriteContext.addSubPath(
                                Pattern.compile("^/t/[^/]+/o/[a-f0-9\\-]+" + subPath)));
            }
        }
    }

    private boolean isOrganizationIdAvailableInTenantPerspective(String requestURI) {

        return Pattern.compile("^/t/[^/]+/o/[a-f0-9\\-]+?").matcher(requestURI).find();
    }
}
