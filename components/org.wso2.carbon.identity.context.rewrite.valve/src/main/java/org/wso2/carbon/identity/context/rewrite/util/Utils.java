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

package org.wso2.carbon.identity.context.rewrite.util;

import com.google.gson.JsonObject;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.organization.management.service.constant.OrganizationManagementConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.wso2.carbon.identity.context.rewrite.constant.RewriteConstants.CONTENT_TYPE_APPLICATION_JSON;
import static org.wso2.carbon.identity.context.rewrite.constant.RewriteConstants.ERROR_CODE;
import static org.wso2.carbon.identity.context.rewrite.constant.RewriteConstants.ERROR_DESCRIPTION;
import static org.wso2.carbon.identity.context.rewrite.constant.RewriteConstants.ERROR_MESSAGE;
import static org.wso2.carbon.identity.context.rewrite.constant.RewriteConstants.ORGANIZATION_PATH_PARAM;

public class Utils {

    public static String getTenantDomainFromURLMapping(Request request) {
        String requestURI = request.getRequestURI();
        String domain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

        if (requestURI.contains("/t/")) {
            String temp = requestURI.substring(requestURI.indexOf("/t/") + 3);
            int index = temp.indexOf('/');
            if (index != -1) {
                temp = temp.substring(0, index);
                domain = temp;
            }
        }
        return domain;
    }

    public static String getOrganizationDomainFromURL(String requestURI) {

        String domain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        String domainInRequestPath = requestURI.substring(requestURI.indexOf(ORGANIZATION_PATH_PARAM) + 3);
        int index = domainInRequestPath.indexOf('/');
        if (index != -1) {
            domainInRequestPath = domainInRequestPath.substring(0, index);
            domain = domainInRequestPath;
        }
        return domain;
    }

    public static void handleErrorResponse(int errorCode, String errorMessage, String errorDescription,
                                           Response response) throws IOException {

        response.setContentType(CONTENT_TYPE_APPLICATION_JSON);
        response.setStatus(errorCode);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        JsonObject errorResponse = new JsonObject();
        errorResponse.addProperty(ERROR_CODE, errorCode);
        errorResponse.addProperty(ERROR_MESSAGE, errorMessage);
        errorResponse.addProperty(ERROR_DESCRIPTION, errorDescription);
        response.getWriter().print(errorResponse);
    }

    public static boolean isOrganizationPerspectiveResourceAccess() {

        // The root tenant domain is set for organization perspective resource access requests.
        String rootTenantDomain = (String) IdentityUtil.threadLocalProperties.get()
                .get(OrganizationManagementConstants.ROOT_TENANT_DOMAIN);
        return StringUtils.isNotEmpty(rootTenantDomain);
    }
}
