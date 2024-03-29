/*
 * Copyright (c) 2023, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.carbon.identity.auth.valve;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnException;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.io.IOException;

import javax.servlet.ServletException;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth10AParams.OAUTH_CONSUMER_KEY;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.CLIENT_ID;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TENANT_NAME_FROM_CONTEXT;

/**
 * This valve is used to resolve the tenant domain of the OAuth application.
 *
 * When tenant qualified urls are not enabled, we need to set the tenant domain of the oauth app to the thread
 * local. This is because with the client id tenant uniqueness improvement, DAO layer requires the tenant domain
 * and client id to retrieve an app when the tenant is not available in the request path. Note that when tenant
 * qualified urls are disabled, client id is unique across the server.
 */
public class OAuthAppTenantResolverValve extends ValveBase {

    private static final Log LOG = LogFactory.getLog(OAuthAppTenantResolverValve.class);
    private static String oAuthServerBaseURL = null;
    private static String oAuth2ServerBaseURL = null;

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {

        try {
            if (isOAuthRequest(request)) {
                String appTenant = "";
                String clientId = request.getParameter(CLIENT_ID);

                if (StringUtils.isEmpty(clientId) && isOAuth10ARequest(request)) {
                    clientId = request.getParameter(OAUTH_CONSUMER_KEY);
                }

                // If empty, try to get the client id from the authorization header.
                if (StringUtils.isEmpty(clientId)) {
                    if (OAuth2Util.isBasicAuthorizationHeaderExists(request)) {
                        try {
                            String[] credentials = OAuth2Util.extractCredentialsFromAuthzHeader(request);
                            if (credentials != null) {
                                clientId = credentials[0];
                            }
                        } catch (OAuthClientAuthnException e) {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Error while extracting credentials from authorization header.", e);
                            }
                        }
                    }
                }

                if (StringUtils.isNotEmpty(clientId)) {
                    try {
                        OAuthAppDO oAuthAppDO = OAuth2Util.getAppInformationByClientIdOnly(clientId);
                        appTenant = OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO);
                    } catch (IdentityOAuth2Exception e) {
                        LOG.error("Error while getting oauth app for client Id: " + clientId, e);
                    } catch (InvalidOAuthClientException e) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("Error while getting oauth app for client Id: " + clientId, e);
                        }
                    }
                }

                // Set the tenant name to thread local properties.
                if (StringUtils.isNotEmpty(appTenant)) {
                    IdentityUtil.threadLocalProperties.get().put(TENANT_NAME_FROM_CONTEXT, appTenant);
                }
            }
            getNext().invoke(request, response);
        } finally {
            // Clear thread local tenant name.
            unsetThreadLocalContextTenantName();
        }
    }

    /**
     * Check whether the request is an OAuth request.
     *
     * @param request Http servlet request.
     * @return True if the request is an OAuth request.
     */
    private boolean isOAuthRequest(Request request) {

        initBaseUrls();
        String requestUrl = request.getRequestURL().toString();
        return StringUtils.isNotEmpty(requestUrl) && (requestUrl.startsWith(oAuth2ServerBaseURL) ||
                requestUrl.startsWith(oAuthServerBaseURL));
    }

    /**
     * Check whether the request is an OAuth 1.0 request.
     *
     * @param request Http servlet request.
     * @return True if the request is an OAuth 1.0 request.
     */
    private boolean isOAuth10ARequest(Request request) {

        String requestUrl = request.getRequestURL().toString();
        return StringUtils.isNotEmpty(requestUrl) && requestUrl.startsWith(oAuthServerBaseURL);
    }

    /**
     * Unset the context tenant name from thread local properties.
     */
    private void unsetThreadLocalContextTenantName() {

        if (IdentityUtil.threadLocalProperties.get().get(TENANT_NAME_FROM_CONTEXT) != null) {
            IdentityUtil.threadLocalProperties.get().remove(TENANT_NAME_FROM_CONTEXT);
        }
    }

    /**
     * Initialize the base urls.
     */
    private void initBaseUrls() {

        if (StringUtils.isEmpty(oAuthServerBaseURL)) {
            oAuthServerBaseURL = IdentityUtil.getServerURL("/oauth", true, true) + "/";
        }
        if (StringUtils.isEmpty(oAuth2ServerBaseURL)) {
            oAuth2ServerBaseURL = IdentityUtil.getServerURL("/oauth2", true, true) + "/";
        }
    }
}
