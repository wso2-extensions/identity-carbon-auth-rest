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

package org.wso2.carbon.identity.auth.service.handler.impl;

import org.apache.catalina.connector.Request;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.slf4j.MDC;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.ProvisioningServiceProviderType;
import org.wso2.carbon.identity.application.common.model.ThreadLocalProvisioningServiceProvider;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationRequest;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil;
import org.wso2.carbon.identity.auth.service.util.Constants;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.dto.OAuth2IntrospectionResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.util.Optional;

import static org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil.isAuthHeaderMatch;
import static org.wso2.carbon.identity.auth.service.util.Constants.AUTHENTICATION_TYPE;
import static org.wso2.carbon.identity.auth.service.util.Constants.IDP_NAME;
import static org.wso2.carbon.identity.auth.service.util.Constants.IS_FEDERATED_USER;
import static org.wso2.carbon.identity.auth.service.util.Constants.OAUTH2_ALLOWED_SCOPES;
import static org.wso2.carbon.identity.auth.service.util.Constants.OAUTH2_VALIDATE_SCOPE;
import static org.wso2.carbon.identity.oauth2.OAuth2Constants.TokenBinderType.SSO_SESSION_BASED_TOKEN_BINDER;

/**
 * OAuth2AccessTokenHandler is for authenticate the request based on Token.
 * canHandle method will confirm whether this request can be handled by this authenticator or not.
 */

public class OAuth2AccessTokenHandler extends AuthenticationHandler {

    private static final Log log = LogFactory.getLog(OAuth2AccessTokenHandler.class);
    private final String OAUTH_HEADER = "Bearer";
    private final String CONSUMER_KEY = "consumer-key";
    private final String SERVICE_PROVIDER = "serviceProvider";
    private final String SERVICE_PROVIDER_TENANT_DOMAIN = "serviceProviderTenantDomain";
    private final String SCIM_ME_ENDPOINT_URI = "scim2/me";

    @Override
    protected AuthenticationResult doAuthenticate(MessageContext messageContext) {

        AuthenticationResult authenticationResult = new AuthenticationResult(AuthenticationStatus.FAILED);
        AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;
        AuthenticationRequest authenticationRequest = authenticationContext.getAuthenticationRequest();
        if (authenticationRequest != null) {

            String authorizationHeader = authenticationRequest.getHeader(HttpHeaders.AUTHORIZATION);
            if (StringUtils.isNotEmpty(authorizationHeader) && authorizationHeader.startsWith(OAUTH_HEADER)) {
                String accessToken = null;
                String[] bearerToken = authorizationHeader.split(" ");

                // Fail the authentication flow if the token is empty or a space else gets the token.
                if (bearerToken.length == 2) {
                    accessToken = bearerToken[1];
                } else {
                    return authenticationResult;
                }

                OAuth2TokenValidationService oAuth2TokenValidationService = new OAuth2TokenValidationService();
                OAuth2TokenValidationRequestDTO requestDTO = new OAuth2TokenValidationRequestDTO();
                OAuth2TokenValidationRequestDTO.OAuth2AccessToken token = requestDTO.new OAuth2AccessToken();
                token.setIdentifier(accessToken);
                token.setTokenType(OAUTH_HEADER);
                requestDTO.setAccessToken(token);

                //TODO: If these values are not set, validation will fail giving an NPE. Need to see why that happens
                OAuth2TokenValidationRequestDTO.TokenValidationContextParam contextParam = requestDTO.new
                        TokenValidationContextParam();
                contextParam.setKey("dummy");
                contextParam.setValue("dummy");

                OAuth2TokenValidationRequestDTO.TokenValidationContextParam[] contextParams =
                        new OAuth2TokenValidationRequestDTO.TokenValidationContextParam[1];
                contextParams[0] = contextParam;
                requestDTO.setContext(contextParams);

                OAuth2IntrospectionResponseDTO oAuth2IntrospectionResponseDTO =
                        oAuth2TokenValidationService.buildIntrospectionResponse(requestDTO);

                IdentityUtil.threadLocalProperties.get()
                        .put(AUTHENTICATION_TYPE, oAuth2IntrospectionResponseDTO.getAut());

                if (!oAuth2IntrospectionResponseDTO.isActive()) {
                    return authenticationResult;
                }

                // If the request is coming to me endpoint, store the token id to the thread local.
                if (Optional.ofNullable(authenticationRequest.getRequest()).map(Request::getRequestURI)
                        .filter(u -> u.toLowerCase().endsWith(SCIM_ME_ENDPOINT_URI)).isPresent()
                        && accessToken != null) {
                    setCurrentTokenIdThreadLocal(getTokenIdFromAccessToken(accessToken));
                }

                TokenBinding tokenBinding = new TokenBinding(oAuth2IntrospectionResponseDTO.getBindingType(),
                        oAuth2IntrospectionResponseDTO.getBindingReference());
                if (!isTokenBindingValid(messageContext, tokenBinding,
                        oAuth2IntrospectionResponseDTO.getClientId(), accessToken)) {
                    return authenticationResult;
                }

                authenticationResult.setAuthenticationStatus(AuthenticationStatus.SUCCESS);

                User authorizedUser = oAuth2IntrospectionResponseDTO.getAuthorizedUser();
                if (authorizedUser != null) {
                    authenticationContext.setUser(authorizedUser);
                    if (authorizedUser instanceof AuthenticatedUser) {
                        IdentityUtil.threadLocalProperties.get()
                                .put(IS_FEDERATED_USER, ((AuthenticatedUser) authorizedUser).isFederatedUser());
                        IdentityUtil.threadLocalProperties.get()
                                .put(IDP_NAME, ((AuthenticatedUser) authorizedUser).getFederatedIdPName());
                    } else {
                        AuthenticatedUser authenticatedUser = new AuthenticatedUser(authorizedUser);
                        IdentityUtil.threadLocalProperties.get()
                                .put(IS_FEDERATED_USER, authenticatedUser.isFederatedUser());
                        IdentityUtil.threadLocalProperties.get()
                                .put(IDP_NAME, authenticatedUser.getFederatedIdPName());
                    }
                }

                authenticationContext.addParameter(CONSUMER_KEY, oAuth2IntrospectionResponseDTO.getClientId());
                authenticationContext.addParameter(OAUTH2_ALLOWED_SCOPES,
                        OAuth2Util.buildScopeArray(oAuth2IntrospectionResponseDTO.getScope()));
                authenticationContext.addParameter(OAUTH2_VALIDATE_SCOPE,
                        AuthConfigurationUtil.getInstance().isScopeValidationEnabled());
                String serviceProvider = null;
                try {
                    serviceProvider =
                            OAuth2Util.getServiceProvider(oAuth2IntrospectionResponseDTO.getClientId()).
                                    getApplicationName();
                } catch (IdentityOAuth2Exception e) {
                    log.error("Error occurred while getting the Service Provider by Consumer key: "
                            + oAuth2IntrospectionResponseDTO.getClientId(), e);
                }

                String serviceProviderTenantDomain = null;
                try {
                    serviceProviderTenantDomain =
                            OAuth2Util.getTenantDomainOfOauthApp(oAuth2IntrospectionResponseDTO.getClientId());
                } catch (InvalidOAuthClientException | IdentityOAuth2Exception e) {
                    log.error("Error occurred while getting the OAuth App tenantDomain by Consumer key: "
                            + oAuth2IntrospectionResponseDTO.getClientId(), e);
                }

                if (serviceProvider != null) {
                    authenticationContext.addParameter(SERVICE_PROVIDER, serviceProvider);
                    if (serviceProviderTenantDomain != null) {
                        authenticationContext.addParameter(SERVICE_PROVIDER_TENANT_DOMAIN, serviceProviderTenantDomain);
                    }

                    MDC.put(SERVICE_PROVIDER, serviceProvider);
                    // Set OAuth service provider details to be consumed by the provisioning framework.
                    setProvisioningServiceProviderThreadLocal(oAuth2IntrospectionResponseDTO.getClientId(),
                            serviceProviderTenantDomain);
                }
            }
        }
        return authenticationResult;
    }

    @Override
    public void init(InitConfig initConfig) {

    }

    @Override
    public String getName() {

        return "OAuthAuthentication";
    }

    @Override
    public boolean isEnabled(MessageContext messageContext) {

        return true;
    }

    @Override
    public int getPriority(MessageContext messageContext) {

        return getPriority(messageContext, 25);
    }

    @Override
    public boolean canHandle(MessageContext messageContext) {

        return isAuthHeaderMatch(messageContext, OAUTH_HEADER);
    }

    /**
     * Validate access token binding value.
     *
     * @param messageContext message context.
     * @param tokenBinding token binding.
     * @param clientId OAuth2 client id.
     * @param accessToken Bearer token from request.
     * @return true if token binding is valid.
     */
    private boolean isTokenBindingValid(MessageContext messageContext, TokenBinding tokenBinding, String clientId,
                                        String accessToken) {

        if (tokenBinding == null || StringUtils.isBlank(tokenBinding.getBindingReference())) {
            if (log.isDebugEnabled()) {
                log.debug("TokenBinding or binding reference is empty.");
            }
            return true;
        }

        OAuthAppDO oAuthAppDO;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId);
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            log.error("Failed to retrieve application information by client id: " + clientId, e);
            return false;
        }

        Request authenticationRequest =
                ((AuthenticationContext) messageContext).getAuthenticationRequest().getRequest();
        if (!oAuthAppDO.isTokenBindingValidationEnabled()) {
            if (log.isDebugEnabled()) {
                log.debug("TokenBinding validation is not enabled for application: " + oAuthAppDO.getApplicationName());
            }
            if (authenticationRequest.getRequestURI().toLowerCase().endsWith(SCIM_ME_ENDPOINT_URI) &&
                    isSSOSessionBasedTokenBinding(tokenBinding.getBindingType())) {
                setCurrentSessionIdThreadLocal(getTokenBindingValueFromAccessToken(accessToken));
            }
            return true;
        }

        if (OAuth2Util.isValidTokenBinding(tokenBinding, authenticationRequest)) {
            if (log.isDebugEnabled()) {
                log.debug("TokenBinding validation is successful. TokenBinding: " + tokenBinding.getBindingType());
            }
            if (authenticationRequest.getRequestURI().toLowerCase().endsWith(SCIM_ME_ENDPOINT_URI) &&
                    isSSOSessionBasedTokenBinding(tokenBinding.getBindingType())) {
                setCurrentSessionIdThreadLocal(tokenBinding.getBindingValue());
            }
            return true;
        }
        if (log.isDebugEnabled()) {
            log.debug("TokenBinding validation is failed.");
        }
        return false;
    }

    /**
     * Get the token binding value which corresponds to the current session identifier from the token when
     * SSO-session-based token binding is enabled.
     *
     * @param accessToken   Bearer token from request.
     * @return Token binding value.
     */
    private String getTokenBindingValueFromAccessToken(String accessToken) {

        String tokenBindingValue = null;
        try {
            AccessTokenDO accessTokenDO = OAuth2Util.findAccessToken(accessToken, false);
            if (accessTokenDO != null) {
                if (accessTokenDO.getTokenBinding() != null &&
                        StringUtils.isNotBlank(accessTokenDO.getTokenBinding().getBindingValue()) &&
                        isSSOSessionBasedTokenBinding(accessTokenDO.getTokenBinding().getBindingType())) {
                    tokenBindingValue = accessTokenDO.getTokenBinding().getBindingValue();
                }
            }
        } catch (IdentityOAuth2Exception e) {
            log.error("Error occurred while getting the access token from the token identifier", e);
        }
        return tokenBindingValue;
    }

    /**
     * Get the token id for a given access token.
     *
     * @param accessToken The access token value.
     * @return The id of the token as a string.
     */
    private String getTokenIdFromAccessToken(String accessToken) {

        String tokenId = null;
        try {
            AccessTokenDO accessTokenDO = OAuth2Util.findAccessToken(accessToken, false);
            if (accessTokenDO != null) {
                tokenId = accessTokenDO.getTokenId();
            }
        } catch (IdentityOAuth2Exception e) {
            log.error("Error occurred while getting the access token id from the token", e);
        }
        return tokenId;
    }

    /**
     * Set token binding value which corresponds to the current session id to a thread local to be used down the flow.
     * @param tokenBindingValue     Token Binding value.
     */
    private void setCurrentSessionIdThreadLocal(String tokenBindingValue) {

        if (StringUtils.isNotBlank(tokenBindingValue)) {
            IdentityUtil.threadLocalProperties.get().put(FrameworkConstants.CURRENT_SESSION_IDENTIFIER,
                    tokenBindingValue);
            if (log.isDebugEnabled()) {
                log.debug("Current session identifier: " + tokenBindingValue + " is added to thread local.");
            }
        }
    }

    /**
     * Set the current access token id to a thread local to be used down the flow.
     *
     * @param accessTokenId The id of the token.
     */
    private void setCurrentTokenIdThreadLocal(String accessTokenId) {

        if (StringUtils.isNotBlank(accessTokenId)) {
            IdentityUtil.threadLocalProperties.get().put(FrameworkConstants.CURRENT_TOKEN_IDENTIFIER, accessTokenId);
            if (log.isDebugEnabled()) {
                log.debug("Current token identifier is added to thread local. Token id: " + accessTokenId);
            }
        }
    }

    /**
     * Check whether the token binding type is 'sso-session'.
     * @param tokenBindingType  Type of the token binding.
     * @return True if 'sso-session', false otherwise.
     */
    private boolean isSSOSessionBasedTokenBinding(String tokenBindingType) {

        return SSO_SESSION_BASED_TOKEN_BINDER.equals(tokenBindingType);
    }

    /**
     * Set the service provider details to a thread local variable to be consumed by the provisioning framework.
     *
     * @param oauthAppConsumerKey           Client ID of the OAuth client application.
     * @param serviceProviderTenantDomain   Tenant Domain of the OAuth application.
     */
    private void setProvisioningServiceProviderThreadLocal(String oauthAppConsumerKey,
                                                           String serviceProviderTenantDomain) {

        if (serviceProviderTenantDomain != null) {
            ThreadLocalProvisioningServiceProvider provisioningServiceProvider =
                    new ThreadLocalProvisioningServiceProvider();
            provisioningServiceProvider.setServiceProviderName(oauthAppConsumerKey);
            provisioningServiceProvider.setServiceProviderType(ProvisioningServiceProviderType.OAUTH);
            provisioningServiceProvider.setTenantDomain(serviceProviderTenantDomain);
            IdentityApplicationManagementUtil.setThreadLocalProvisioningServiceProvider(provisioningServiceProvider);
        }
    }
}
