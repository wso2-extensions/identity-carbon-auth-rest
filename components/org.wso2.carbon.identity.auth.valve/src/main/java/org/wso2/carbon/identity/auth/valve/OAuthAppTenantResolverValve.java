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

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnException;
import org.wso2.carbon.identity.oauth2.dto.OAuth2ClientApplicationDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.io.IOException;
import java.text.ParseException;
import java.util.Optional;

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
            String clientId = isOAuthRequest(request) ? extractClientIDFromOauthRequest(request)
                    : extractClientIDFromAuthzHeader(request);

            String appTenant = "";
            OAuthAppDO oAuthAppDO = null;
            if (StringUtils.isNotEmpty(clientId)) {
                try {
                    oAuthAppDO = OAuth2Util.getAppInformationByClientIdOnly(clientId);
                } catch (IdentityOAuth2Exception e) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Error while getting oauth app for client Id: " + clientId, e);
                    }
                } catch (InvalidOAuthClientException e) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Could not find an application with given client Id: " + clientId, e);
                    }
                }
                appTenant = OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO);
            }

            // If no client application is found for the given client ID and a basic auth header with
            // resource-owner credentials exists, extract the tenant domain from the username.
            if (oAuthAppDO == null && OAuth2Util.isBasicAuthorizationHeaderExists(request)) {
                appTenant = extractTenantDomainFromUserName(request);
            }

            if (StringUtils.isNotEmpty(appTenant)) {
                IdentityUtil.threadLocalProperties.get().put(TENANT_NAME_FROM_CONTEXT, appTenant);
                PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
                carbonContext.setTenantDomain(appTenant);
                carbonContext.setTenantId(IdentityTenantUtil.getTenantId(appTenant));
                startTenantFlow(appTenant);
            }

            getNext().invoke(request, response);
        } finally {
            // Clear thread local tenant name.
            unsetThreadLocalContextTenantName();
        }
    }

    /**
     * Starts a tenant flow after resolving the current tenant domain when tenant qualified URLs are disabled.
     *
     * @param tenantDomain Tenant Domain.
     */
    private void startTenantFlow(String tenantDomain) {

        String userId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getUserId();
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);

        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(tenantId);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUserId(userId);
    }

    /**
     * Extracts the client ID from oauth request.
     *
     * @param request Request.
     * @return client ID.
     */
    private String extractClientIDFromOauthRequest(Request request) {

        String clientId = "";
        clientId = request.getParameter(CLIENT_ID);

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

        return clientId;
    }

    /**
     * Extracts the client ID from non oauth request.
     * This method validates the opaque token or the JWT in the authorization header and extracts the client ID
     * of the application owning the token.
     *
     * @param request Request.
     * @return Client ID.
     */
    private String extractClientIDFromAuthzHeader(Request request) {

        String bearerToken = null;
        String clientId = "";
        try {
            bearerToken = OAuth2Util.extractBearerTokenFromAuthzHeader(request);
        } catch (OAuthClientAuthnException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error while extracting token from authorization header.", e);
            }
        }

        if (StringUtils.isNotBlank(bearerToken)) {
            if (OAuth2Util.isJWT(bearerToken)) {
                clientId =  resolveClientIdFromJWT(bearerToken);
            } else {
                clientId = resolveClientIdFromOpaqueToken(bearerToken);
            }
        }

        return clientId;
    }

    /**
     * Resolves client ID from the JWT in authorization header.
     *
     * @param bearerToken Bearer token.
     * @return Client ID.
     */
    private String resolveClientIdFromJWT(String bearerToken) {

        String clientId = "";
        try {
            JWT decodedToken = JWTParser.parse(bearerToken);
            clientId = decodedToken.getJWTClaimsSet().getStringClaim("client_id");
        } catch (ParseException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error while extracting client id from JWT.", e);
            }
        }

        return clientId;
    }

    /**
     * Resolves client ID from the opaque token in authorization header.
     *
     * @param bearerToken Bearer token.
     * @return Client ID.
     */
    private String resolveClientIdFromOpaqueToken(String bearerToken) {

        OAuth2TokenValidationRequestDTO validationRequest = new OAuth2TokenValidationRequestDTO();

        OAuth2TokenValidationRequestDTO.OAuth2AccessToken accessToken = validationRequest.new OAuth2AccessToken();
        accessToken.setIdentifier(bearerToken);
        accessToken.setTokenType("Bearer");
        validationRequest.setAccessToken(accessToken);

        // If opaque token is valid, retrieve the client application.
        OAuth2ClientApplicationDTO clientApplication = new OAuth2TokenValidationService().
                findOAuthConsumerIfTokenIsValid(validationRequest);

        return Optional.ofNullable(clientApplication)
                .map(OAuth2ClientApplicationDTO::getConsumerKey)
                .orElse(null);
    }

    /**
     * Extract tenant domain from username of basic authz header.
     *
     * @param request Request.
     * @return Tenant domain.
     */
    private String extractTenantDomainFromUserName(Request request) {

        String tenantQualifiedUsername = "";
        try {
            String[] credentials = OAuth2Util.extractCredentialsFromAuthzHeader(request);
            if (credentials != null) {
                tenantQualifiedUsername = credentials[0];
            }
        } catch (OAuthClientAuthnException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error while extracting credentials from authorization header.", e);
            }
        }

        return StringUtils.substringAfter(tenantQualifiedUsername, "@");
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
