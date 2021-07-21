/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.auth.service.handler.impl;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.auth.service.exception.AuthenticationFailException;
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.nio.charset.Charset;

import static org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil.isAuthHeaderMatch;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OauthAppStates.APP_STATE_ACTIVE;

/**
 * BasicClientAuthenticationHandler is for authenticate the request based on Basic Authentication
 * using the client credentials.
 * canHandle method will confirm whether this request can be handled by this authenticator or not.
 */
public class BasicClientAuthenticationHandler extends AuthenticationHandler {

    private static final Log log = LogFactory.getLog(BasicClientAuthenticationHandler.class);
    private final String BASIC_AUTH_HEADER = "Basic";

    @Override
    public void init(InitConfig initConfig) {

    }

    @Override
    public String getName() {

        return "BasicClientAuthentication";
    }

    @Override
    public int getPriority(MessageContext messageContext) {

        return getPriority(messageContext, 99);
    }

    @Override
    public boolean canHandle(MessageContext messageContext) {

        return isAuthHeaderMatch(messageContext, BASIC_AUTH_HEADER);
    }

    @Override
    public boolean isEnabled(MessageContext messageContext) {

        return true;
    }

    @Override
    protected AuthenticationResult doAuthenticate(MessageContext messageContext) throws AuthenticationFailException {

        AuthenticationResult authenticationResult = new AuthenticationResult(AuthenticationStatus.FAILED);
        AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;
        String authorizationHeader = authenticationContext.getAuthenticationRequest().
                getHeader(HttpHeaders.AUTHORIZATION);

        if (authorizationHeader != null){
            String[] splitAuthorizationHeader = authorizationHeader.split(" ");
            if (splitAuthorizationHeader.length == 2) {
                byte[] decodedAuthHeader = Base64.decodeBase64(splitAuthorizationHeader[1].getBytes());
                String authHeader = new String(decodedAuthHeader, Charset.defaultCharset());
                String[] credentials = authHeader.split(":", 2);

                if (credentials.length == 2 && StringUtils.isNotBlank(credentials[0]) &&
                        StringUtils.isNotBlank(credentials[1])) {
                    String clientId = credentials[0];
                    String clientSecret = credentials[1];

                    try {
                        if (log.isDebugEnabled()) {
                            log.debug("Authenticating application with client ID: " + clientId
                                    + " with client secret.");
                        }

                        OAuthAppDO oAuthAppDO = getOAuthApplication(clientId);
                        String tenantDomainOfApp = OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO);
                        validateRequestTenantDomain(tenantDomainOfApp);

                        if (OAuth2Util.authenticateClient(clientId, clientSecret)) {
                            authenticationResult.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
                        } else {
                            authenticationResult.setAuthenticationStatus(AuthenticationStatus.FAILED);
                        }
                    } catch (IdentityOAuthAdminException e) {
                        String errorMessage = "Error while authenticating application with client ID: " + clientId;
                        log.error(errorMessage, e);
                        throw new AuthenticationFailException(errorMessage, e);
                    } catch (InvalidOAuthClientException | IdentityOAuth2Exception e) {
                        String errorMessage = "Invalid client: " + clientId;
                        log.error(errorMessage, e);
                        throw new AuthenticationFailException(errorMessage, e);
                    }
                } else {
                    String errorMessage = "Error occurred while trying to authenticate. The OAuth application credentials "
                            + "are not defined correctly.";
                    log.error(errorMessage);
                    throw new AuthenticationFailException(errorMessage);
                }
            } else {
                String errorMessage = "Error occurred while trying to authenticate. The " + HttpHeaders.AUTHORIZATION +
                        " header values are not defined correctly.";
                log.error(errorMessage);
                throw new AuthenticationFailException(errorMessage);
            }
        } else {
            String errorMessage = "Authorization Header is null.";
            log.error(errorMessage);
            throw new AuthenticationFailException(errorMessage);
        }
        return authenticationResult;
    }

    private OAuthAppDO getOAuthApplication(String consumerKey) throws InvalidOAuthClientException,
            IdentityOAuth2Exception {

        OAuthAppDO authAppDO = OAuth2Util.getAppInformationByClientId(consumerKey);
        String appState = authAppDO.getState();
        if (StringUtils.isEmpty(appState)) {
            if (log.isDebugEnabled()) {
                log.debug("A valid OAuth client could not be found for client_id: " + consumerKey);
            }
            throw new InvalidOAuthClientException("A valid OAuth client not found for client_id: " + consumerKey);
        }

        if (!APP_STATE_ACTIVE.equalsIgnoreCase(appState)) {
            if (log.isDebugEnabled()) {
                log.debug("App is not in active state in client ID: " + consumerKey + ". App state is:" + appState);
            }
            throw new InvalidOAuthClientException("Oauth application is not in active state");
        }
        return authAppDO;
    }

    private void validateRequestTenantDomain(String tenantDomainOfApp) throws InvalidOAuthClientException {

        if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
            String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();;
            if (!StringUtils.equals(tenantDomain, tenantDomainOfApp)) {
                throw new InvalidOAuthClientException("A valid client with the given client_id cannot be found in " +
                        "tenantDomain: " + tenantDomain);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Valid client found for given client_id in tenantDomain: " + tenantDomain);
                }
            }
        }
    }
}
