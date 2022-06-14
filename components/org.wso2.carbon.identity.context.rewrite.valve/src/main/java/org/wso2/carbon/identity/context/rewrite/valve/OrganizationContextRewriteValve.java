/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.com).
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
import org.apache.axiom.om.OMElement;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.slf4j.MDC;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import javax.xml.namespace.QName;

import static org.wso2.carbon.identity.core.util.IdentityCoreConstants.TENANT_NAME_FROM_CONTEXT;

public class OrganizationContextRewriteValve extends ValveBase {

    private static final String TENANT_DOMAIN = "tenantDomain";
    private static final String TENANT_ID = "tenantId";
    private static final String ORGANIZATION_PATH_PARAM = "/o/";
    private static Map<String, List<String>> orgContextsToRewrite;

    @Override
    protected synchronized void startInternal() throws LifecycleException {

        super.startInternal();
        orgContextsToRewrite = getOrgContextsToRewrite();
    }

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {

        String requestURI = request.getRequestURI();
        String contextToForward = null;
        boolean isOrgUrl = false;

        if (StringUtils.startsWith(requestURI, ORGANIZATION_PATH_PARAM)) {

            for (Map.Entry<String, List<String>> entry : orgContextsToRewrite.entrySet()) {
                String basePath = entry.getKey();
                Pattern orgPattern = Pattern.compile("^" + ORGANIZATION_PATH_PARAM + "([^/]+)" + basePath);
                if (orgPattern.matcher(requestURI).find() || orgPattern.matcher(requestURI + "/").find()) {
                    isOrgUrl = true;
                    contextToForward = basePath;
                    List<String> subPaths = entry.getValue();
                    if (CollectionUtils.isNotEmpty(subPaths)) {
                        boolean subPathSupported = false;
                        for (String subPath : subPaths) {
                            if (StringUtils.contains(requestURI, subPath)) {
                                subPathSupported = true;
                                break;
                            }
                        }
                        if (!subPathSupported) {
                            handleErrorResponse(response, HttpServletResponse.SC_NOT_FOUND);
                            return;
                        }
                    }
                    break;
                }
            }
            if (!isOrgUrl) {
                handleErrorResponse(response, HttpServletResponse.SC_NOT_FOUND);
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

            String orgDomain = getOrgDomainFromURL(requestURI);

            String dispatchLocation = "/" +
                    requestURI.replace(ORGANIZATION_PATH_PARAM + orgDomain + contextToForward, StringUtils.EMPTY);
            request.getContext().setCrossContext(true);
            request.getServletContext().getContext(contextToForward)
                    .getRequestDispatcher(dispatchLocation).forward(request, response);
        } finally {
            IdentityUtil.threadLocalProperties.get().remove(TENANT_NAME_FROM_CONTEXT);
            unsetMDCThreadLocals();
        }
    }

    private void unsetMDCThreadLocals() {

        MDC.remove(TENANT_DOMAIN);
        MDC.remove(TENANT_ID);
    }

    private Map<String, List<String>> getOrgContextsToRewrite() {

        Map<String, List<String>> rewriteContexts = new HashMap<>();
        OMElement orgContextsToRewrite = IdentityConfigParser.getInstance().getConfigElement("OrgContextsToRewrite");
        if (orgContextsToRewrite != null) {
            OMElement webApp = orgContextsToRewrite.getFirstChildWithName(
                    new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, "WebApp"));
            if (webApp != null) {
                Iterator contexts = webApp.getChildrenWithName(
                        new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, "Context"));
                if (contexts != null) {
                    while (contexts.hasNext()) {
                        OMElement context = (OMElement) contexts.next();
                        OMElement basePath = context.getFirstChildWithName(
                                new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, "Path"));
                        if (basePath != null) {
                            OMElement contextToForward = context.getFirstChildWithName(
                                    new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, "ContextToForward"));
                            if (contextToForward != null) {
                                Iterator subPaths = contextToForward.getChildrenWithName(
                                        new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, "Path"));
                                if (subPaths != null) {
                                    List<String> subPathList = new ArrayList<>();
                                    while (subPaths.hasNext()) {
                                        OMElement subPath = (OMElement) subPaths.next();
                                        subPathList.add(subPath.getText());
                                    }
                                    rewriteContexts.put(basePath.getText(), subPathList);
                                }
                            } else {
                                rewriteContexts.put(basePath.getText(), null);
                            }
                        }
                    }
                }
            }
        }
        return rewriteContexts;
    }

    private void handleErrorResponse(Response response, int error) throws IOException {

        response.setContentType("application/json");
        response.setStatus(error);
        response.setCharacterEncoding("UTF-8");
        JsonObject errorResponse = new JsonObject();
        String errorMsg = "Unsupported organization specific routing endpoint";
        errorResponse.addProperty("code", error);
        errorResponse.addProperty("message", errorMsg);
        errorResponse.addProperty("description", errorMsg);
        response.getWriter().print(errorResponse);
    }

    public static String getOrgDomainFromURL(String requestURI) {

        String domain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        String temp = requestURI.substring(requestURI.indexOf("/o/") + 3);
        int index = temp.indexOf('/');
        if (index != -1) {
            temp = temp.substring(0, index);
            domain = temp;
        }
        return domain;
    }
}
