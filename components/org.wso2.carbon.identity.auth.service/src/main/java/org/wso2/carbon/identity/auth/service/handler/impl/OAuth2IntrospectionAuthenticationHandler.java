/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationRequest;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.auth.service.exception.AuthClientException;
import org.wso2.carbon.identity.auth.service.exception.AuthServerException;
import org.wso2.carbon.identity.auth.service.exception.AuthenticationFailException;
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.auth.service.util.Constants;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthConsumerDAO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import java.nio.charset.Charset;

/**
 * OAuth2IntrospectionAuthenticationHandler is for authenticate the request based on consumer key and secret.
 * canHandle method will confirm whether this request can be handled by this authenticator or not.
 */
public class OAuth2IntrospectionAuthenticationHandler extends AuthenticationHandler {

    private static final Log log = LogFactory.getLog(OAuth2IntrospectionAuthenticationHandler.class);
    private final String INTROSPECTION_URI = "oauth2/introspect";
    private final String BASIC_AUTH_HEADER = "Basic";
    private final String CONSUMER_KEY = "consumer-key";

    @Override
    protected AuthenticationResult doAuthenticate(MessageContext messageContext) throws AuthServerException,
            AuthenticationFailException, AuthClientException {

        BasicAuthenticationHandler basicAuthHandler = new BasicAuthenticationHandler();
        AuthenticationResult authenticationResult = basicAuthHandler.doAuthenticate(messageContext);

        if(authenticationResult.getAuthenticationStatus().equals(AuthenticationStatus.SUCCESS)) {
            return authenticationResult;
        }

        authenticationResult = new AuthenticationResult(AuthenticationStatus.FAILED);
        AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;
        String authorizationHeader = authenticationContext.getAuthenticationRequest().
                getHeader(HttpHeaders.AUTHORIZATION);

        String[] splitAuthorizationHeader = authorizationHeader.split(" ");
        if (splitAuthorizationHeader.length == 2) {
            byte[] decodedAuthHeader = Base64.decodeBase64(splitAuthorizationHeader[1].getBytes());
            String[] splitCredentials = new String(decodedAuthHeader, Charset.defaultCharset())
                    .split(Constants.AUTH_HEADER_SEPERATOR, 2);
            if (splitCredentials.length == 2) {
                String clientId = splitCredentials[0];
                String clientSecret = splitCredentials[1];

                try {
                    boolean isAuthenticated = OAuth2Util.authenticateClient(clientId, clientSecret);
                    if ( isAuthenticated ) {
                        authenticationResult.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
                        if ( log.isDebugEnabled() ) {
                            log.debug("Basic authentication success for client : "+ clientId + ".");
                        }

                        OAuthConsumerDAO oAuthConsumerDAO = new OAuthConsumerDAO();
                        String username = oAuthConsumerDAO.getAuthenticatedUsername(clientId, clientSecret);
                        if(StringUtils.isNotBlank(username)) {
                            User user = new User();
                            user.setUserName(MultitenantUtils.getTenantAwareUsername(username));
                            user.setTenantDomain(MultitenantUtils.getTenantDomain(username));
                            authenticationContext.setUser(user);
                        }

                        authenticationContext.addParameter(CONSUMER_KEY, clientId);
                    }
                } catch (InvalidOAuthClientException | IdentityOAuth2Exception e) {
                    throw new AuthClientException("Invalid Client : " + clientId);
                } catch (IdentityOAuthAdminException e) {
                    throw new AuthClientException("Error while authenticating client");
                }
            } else {
                String errorMessage = "An error occurred while trying to authenticate and auth user credentials " +
                        "are not defined correctly.";
                log.error(errorMessage);
                throw new AuthClientException(errorMessage);
            }
        } else {
            String errorMessage = "An error occurred while trying to authenticate and  " + HttpHeaders.AUTHORIZATION
                    + " header values are not defined correctly.";
            log.error(errorMessage);
            throw new AuthClientException(errorMessage);
        }
        return authenticationResult;
    }

    @Override
    public void init(InitConfig initConfig) {

    }

    @Override
    public String getName() {

        return "OAuthIntrospectionAuthentication";
    }

    @Override
    public boolean isEnabled(MessageContext messageContext) {

        return true;
    }

    @Override
    public int getPriority(MessageContext messageContext) {

        return getPriority(messageContext, 90);
    }

    @Override
    public boolean canHandle(MessageContext messageContext) {

        AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;
        AuthenticationRequest authenticationRequest = authenticationContext.getAuthenticationRequest();
        String authorizationHeader;
        if(authenticationRequest != null) {
            authorizationHeader = authenticationRequest.getHeader(HttpHeaders.AUTHORIZATION);
            return StringUtils.containsIgnoreCase(authenticationRequest.getRequestUri(), INTROSPECTION_URI) &&
                    StringUtils.isNotEmpty(authorizationHeader) && authorizationHeader.startsWith(BASIC_AUTH_HEADER);
        }
        return false;
    }
}
