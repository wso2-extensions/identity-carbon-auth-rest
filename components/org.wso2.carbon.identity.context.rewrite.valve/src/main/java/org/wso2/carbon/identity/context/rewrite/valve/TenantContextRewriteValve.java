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

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.context.rewrite.bean.RewriteContext;
import org.wso2.carbon.identity.context.rewrite.util.Utils;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import javax.servlet.ServletException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class TenantContextRewriteValve extends ValveBase {

    private static final String TENANT_NAME_FROM_CONTEXT = "TenantNameFromContext";
    private static List<RewriteContext> contextsToRewrite;

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        String requestURI = request.getRequestURI();

        if (contextsToRewrite == null) {
            contextsToRewrite = getContextsToRewrite();
        }

        String contextToForward = null;
        boolean isContextRewrite = false;
        boolean isWebApp = false;

        //Get the rewrite contexts and check whether request URI contains any of rewrite contains.
        for (RewriteContext context : contextsToRewrite) {
            Pattern pattern = Pattern.compile("/t/([^/]+)" + context.getContext());
            Matcher matcher = pattern.matcher(requestURI);
            if (matcher.find()) {
                isContextRewrite = true;
                isWebApp = context.isWebApp();
                contextToForward = context.getContext();
                break;
            }
        }

        //request URI is not a rewrite one
        if (!isContextRewrite) {
            getNext().invoke(request, response);
            return;
        }

        try {
            String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            IdentityUtil.threadLocalProperties.get().put(TENANT_NAME_FROM_CONTEXT, tenantDomain);

            if (isWebApp) {
                String dispatchLocation;
                //Need to rewrite
                dispatchLocation = requestURI.replace("/t/" + tenantDomain + contextToForward, "");
                request.getContext().setCrossContext(true);
                request.getServletContext().getContext(contextToForward).getRequestDispatcher("/" + dispatchLocation).forward
                        (request, response);

            } else {
                String carbonWebContext = ServerConfiguration.getInstance().getFirstProperty("WebContextRoot");
                if (requestURI.contains(carbonWebContext)) {
                    requestURI = requestURI.replace(carbonWebContext + "/", "");
                }
                //Servlet
                requestURI = requestURI.replace("/t/" + tenantDomain, "");
                request.getRequestDispatcher(requestURI).forward(request, response);
            }

        } finally {
            IdentityUtil.threadLocalProperties.get().remove(TENANT_NAME_FROM_CONTEXT);
        }
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
}
