/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.context.rewrite.internal;

import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.context.rewrite.bean.OrganizationRewriteContext;
import org.wso2.carbon.identity.context.rewrite.bean.RewriteContext;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.organization.management.service.OrganizationManagementInitialize;
import org.wso2.carbon.user.core.service.RealmService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

import static org.wso2.carbon.identity.context.rewrite.constant.RewriteConstants.ORGANIZATION_PATH_PARAM;
import static org.wso2.carbon.identity.core.util.IdentityCoreConstants.ENABLE_TENANT_QUALIFIED_URLS;

@Component(
         name = "identity.context.rewrite.valve.component", 
         immediate = true)
public class ContextRewriteValveServiceComponent {

    private static final Log log = LogFactory.getLog(ContextRewriteValveServiceComponent.class);

    @Activate
    protected void activate(ComponentContext context) {
        if (log.isDebugEnabled()) {
            log.debug("ContextRewriteValveServiceComponent is activated.");
        }
        loadPageNotFoundErrorPage();
        ContextRewriteValveServiceComponentHolder.getInstance()
                .setOrganizationRewriteContexts(getOrgContextsToRewrite());
        // Initialize the tenant context rewrite valve.
        ContextRewriteValveServiceComponentHolder.getInstance().setContextsToRewrite(getContextsToRewrite());
        ContextRewriteValveServiceComponentHolder.getInstance()
                .setContextListToOverwriteDispatch(getContextListToOverwriteDispatchLocation());
        ContextRewriteValveServiceComponentHolder.getInstance()
                .setIgnorePathListForOverwriteDispatch(getIgnorePathListForOverwriteDispatch());
        ContextRewriteValveServiceComponentHolder.getInstance()
                .setTenantQualifiedUrlsEnabled(isTenantQualifiedUrlsEnabled());
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {
        if (log.isDebugEnabled()) {
            log.debug("ContextRewriteValveServiceComponent is deactivated.");
        }
    }

    @Reference(
             name = "user.realmservice.default", 
             service = org.wso2.carbon.user.core.service.RealmService.class, 
             cardinality = ReferenceCardinality.MANDATORY, 
             policy = ReferencePolicy.DYNAMIC, 
             unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Setting the Realm Service.");
        }
        ContextRewriteValveServiceComponentHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Unsetting the Realm Service.");
        }
        ContextRewriteValveServiceComponentHolder.getInstance().setRealmService(null);
    }

    @Reference(
            name = "organization.mgt.initialize.service",
            service = OrganizationManagementInitialize.class,
            cardinality = ReferenceCardinality.OPTIONAL,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationManagementEnablingService"
    )
    protected void setOrganizationManagementEnablingService(
            OrganizationManagementInitialize organizationManagementInitializeService) {

        ContextRewriteValveServiceComponentHolder.getInstance()
                .setOrganizationManagementEnable(organizationManagementInitializeService);
    }

    protected void unsetOrganizationManagementEnablingService(
            OrganizationManagementInitialize organizationManagementInitializeInstance) {

        ContextRewriteValveServiceComponentHolder.getInstance().setOrganizationManagementEnable(null);
    }

    @Reference(
            name = "identityCoreInitializedEventService",
            service = IdentityCoreInitializedEvent.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityCoreInitializedEventService"
    )
    protected void setIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started */
    }

    protected void unsetIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started */
    }

    private void loadPageNotFoundErrorPage() {

        String errorPage = "Page Not Found";
        try {
            Path pageNotFoundHtmlResponse =
                    Paths.get(CarbonUtils.getCarbonHome(), "repository", "resources", "identity", "pages",
                            "page_not_found.html");
            if (!Files.exists(pageNotFoundHtmlResponse) ||
                    !Files.isRegularFile(pageNotFoundHtmlResponse)) {
                if (log.isDebugEnabled()) {
                    log.debug("pageNotFoundHtmlResponse is not present at: " + pageNotFoundHtmlResponse);
                }
            }
            File file = new File(pageNotFoundHtmlResponse.toString());
            errorPage = FileUtils.readFileToString(file, StandardCharsets.UTF_8);
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug("File page_not_found.html not found. The default content will be used " +
                        "as the error page content.");
            }
        }
        ContextRewriteValveServiceComponentHolder.getInstance().setPageNotFoundErrorPage(errorPage);
    }

    private List<OrganizationRewriteContext> getOrgContextsToRewrite() {

        List<OrganizationRewriteContext> organizationRewriteContexts = new ArrayList<>();
        Map<String, Object> configuration = IdentityConfigParser.getInstance().getConfiguration();
        Object webAppBasePathContexts = configuration.get("OrgContextsToRewrite.WebApp.Context.BasePath");
        setOrganizationRewriteContexts(organizationRewriteContexts, webAppBasePathContexts, true);

        Object webAppSubPathContexts = configuration.get("OrgContextsToRewrite.WebApp.Context.SubPaths.Path");
        setSubPathContexts(organizationRewriteContexts, webAppSubPathContexts);

        Object servletBasePathContexts = configuration.get("OrgContextsToRewrite.Servlet.Context");
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

        if (subPathContexts != null) {
            if (subPathContexts instanceof ArrayList) {
                for (String subPath : (ArrayList<String>) subPathContexts) {
                    Optional<OrganizationRewriteContext> maybeOrgRewriteContext = organizationRewriteContexts.stream()
                            .filter(rewriteContext -> subPath.startsWith(rewriteContext.getContext()))
                            .max(Comparator.comparingInt(rewriteContext -> rewriteContext.getContext().length()));
                    maybeOrgRewriteContext.ifPresent(
                            organizationRewriteContext -> organizationRewriteContext.addSubPath(
                                    Pattern.compile("^" + ORGANIZATION_PATH_PARAM + "([^/]+)" + subPath)));
                }
            }
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

    private boolean isTenantQualifiedUrlsEnabled() {

        Map<String, Object> configuration = IdentityConfigParser.getInstance().getConfiguration();
        String enableTenantQualifiedUrls = (String) configuration.get(ENABLE_TENANT_QUALIFIED_URLS);
        return Boolean.parseBoolean(enableTenantQualifiedUrls);
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
}

