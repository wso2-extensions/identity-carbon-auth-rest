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
package org.wso2.carbon.identity.auth.service.module;

import java.io.Serializable;
import java.util.List;

/**
 * Model class to hold resource access configs.
 */
public class ResourceConfig implements Serializable {

    private String context;
    private String httpMethod;
    private boolean isSecured;
    private boolean isCrossTenantAllowed;
    private String permissions;
    private List<String> scopes;
    private String accessControl;
    // Comma separated list of allowed authentication handler names. If all handlers are engaged the value is 'all'
    private String allowedAuthHandlers;
    private List<String> crossAccessAllowedTenants;

    public String getContext() {
        return context;
    }

    public void setContext(String context) {
        this.context = context;
    }

    public String getHttpMethod() {
        return httpMethod;
    }

    public void setHttpMethod(String httpMethod) {
        this.httpMethod = httpMethod;
    }

    public boolean isSecured() {
        return isSecured;
    }

    public void setIsSecured(boolean isSecured) {
        this.isSecured = isSecured;
    }

    public boolean isCrossTenantAllowed() {
        return isCrossTenantAllowed;
    }

    public void setIsCrossTenantAllowed(boolean isCrossTenantAllowed) {
        this.isCrossTenantAllowed = isCrossTenantAllowed;
    }

    public List<String> getCrossAccessAllowedTenants() {

        return crossAccessAllowedTenants;
    }

    public void setCrossAccessAllowedTenants(List<String> crossAccessAllowedTenants) {

        this.crossAccessAllowedTenants = crossAccessAllowedTenants;
    }

    public String getPermissions() {
        return permissions;
    }

    public void setPermissions(String permissions) {
        this.permissions = permissions;
    }

    public String getAllowedAuthHandlers() {

        return allowedAuthHandlers;
    }

    public void setAllowedAuthHandlers(String allowedAuthHandlers) {

        this.allowedAuthHandlers = allowedAuthHandlers;
    }

    public List<String> getScopes() {

        return scopes;
    }

    public void setScopes(List<String> scopes) {

        this.scopes = scopes;
    }

    public String getAccessControl() {
        return accessControl;
    }

    public void setAccessControl(String accessControl) {
        this.accessControl = accessControl;
    }
}
