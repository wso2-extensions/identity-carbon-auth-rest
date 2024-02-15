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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.context.rewrite.bean.OrganizationRewriteContext;
import org.wso2.carbon.identity.context.rewrite.bean.RewriteContext;
import org.wso2.carbon.identity.organization.management.service.OrganizationManagementInitialize;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.List;

public class ContextRewriteValveServiceComponentHolder {

    private static ContextRewriteValveServiceComponentHolder instance = new ContextRewriteValveServiceComponentHolder();
    private RealmService realmService;
    private String pageNotFoundErrorPage;
    private static final Log log = LogFactory.getLog(ContextRewriteValveServiceComponentHolder.class);
    private boolean isOrganizationManagementEnable;

    private List<OrganizationRewriteContext> organizationRewriteContexts;
    private List<RewriteContext> contextsToRewrite;
    private List<String> contextListToOverwriteDispatch;
    private List<String> ignorePathListForOverwriteDispatch;
    private boolean isTenantQualifiedUrlsEnabled;

    private ContextRewriteValveServiceComponentHolder() {

    }

    public static ContextRewriteValveServiceComponentHolder getInstance() {

        return instance;
    }

    public RealmService getRealmService() {

        if (realmService == null) {
            throw new RuntimeException("RealmService is null");
        }

        return realmService;
    }

    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }

    /**
     * Get default templates from file artifacts.
     *
     * @return Default templates in files.
     */
    public String getPageNotFoundErrorPage() {

        return pageNotFoundErrorPage;
    }

    public void setPageNotFoundErrorPage(String pageNotFoundErrorPage) {

        this.pageNotFoundErrorPage = pageNotFoundErrorPage;
    }

    /**
     * Get is organization management enabled.
     *
     * @return True if organization management is enabled.
     */
    public boolean isOrganizationManagementEnabled() {

        return isOrganizationManagementEnable;
    }

    /**
     * Set organization management enable/disable state.
     *
     * @param organizationManagementInitializeService OrganizationManagementInitializeInstance.
     */
    public void setOrganizationManagementEnable(
            OrganizationManagementInitialize organizationManagementInitializeService) {

        if (organizationManagementInitializeService != null) {
            isOrganizationManagementEnable = organizationManagementInitializeService.isOrganizationManagementEnabled();
        }
    }

    public List<OrganizationRewriteContext> getOrganizationRewriteContexts() {

        return organizationRewriteContexts;
    }

    public void setOrganizationRewriteContexts(
            List<OrganizationRewriteContext> organizationRewriteContexts) {

        this.organizationRewriteContexts = organizationRewriteContexts;
    }

    public List<RewriteContext> getContextsToRewrite() {

        return contextsToRewrite;
    }

    public void setContextsToRewrite(List<RewriteContext> contextsToRewrite) {

        this.contextsToRewrite = contextsToRewrite;
    }

    public List<String> getContextListToOverwriteDispatch() {

        return contextListToOverwriteDispatch;
    }

    public void setContextListToOverwriteDispatch(List<String> contextListToOverwriteDispatch) {

        this.contextListToOverwriteDispatch = contextListToOverwriteDispatch;
    }

    public List<String> getIgnorePathListForOverwriteDispatch() {

        return ignorePathListForOverwriteDispatch;
    }

    public void setIgnorePathListForOverwriteDispatch(List<String> ignorePathListForOverwriteDispatch) {

        this.ignorePathListForOverwriteDispatch = ignorePathListForOverwriteDispatch;
    }

    public boolean isTenantQualifiedUrlsEnabled() {

        return isTenantQualifiedUrlsEnabled;
    }

    public void setTenantQualifiedUrlsEnabled(boolean tenantQualifiedUrlsEnabled) {

        this.isTenantQualifiedUrlsEnabled = tenantQualifiedUrlsEnabled;
    }
}
