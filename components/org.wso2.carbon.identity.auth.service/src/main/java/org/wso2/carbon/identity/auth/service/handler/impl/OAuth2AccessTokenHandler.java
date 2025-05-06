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

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.catalina.connector.Request;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.json.JSONObject;
import org.slf4j.MDC;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.ProvisioningServiceProviderType;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ThreadLocalProvisioningServiceProvider;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationRequest;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.auth.service.module.ResourceConfig;
import org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil;
import org.wso2.carbon.identity.auth.service.util.Constants;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.ApplicationActor;
import org.wso2.carbon.identity.core.context.model.UserActor;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Constants;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.dto.OAuth2IntrospectionResponseDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.RefreshTokenValidator;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;

import java.text.ParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.wso2.carbon.identity.application.mgt.ApplicationConstants.MY_ACCOUNT_APPLICATION_CLIENT_ID;
import static org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil.isAuthHeaderMatch;
import static org.wso2.carbon.identity.auth.service.util.Constants.GET;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.IMPERSONATING_ACTOR;
import static org.wso2.carbon.identity.oauth2.OAuth2Constants.TokenBinderType.SSO_SESSION_BASED_TOKEN_BINDER;
import static org.wso2.carbon.identity.oauth2.impersonation.utils.Constants.IMPERSONATION_SCOPE_NAME;

/**
 * OAuth2AccessTokenHandler is for authenticate the request based on Token.
 * canHandle method will confirm whether this request can be handled by this authenticator or not.
 */

public class OAuth2AccessTokenHandler extends AuthenticationHandler {

    private static final Log log = LogFactory.getLog(OAuth2AccessTokenHandler.class);
    private static final Log AUDIT = CarbonConstants.AUDIT_LOG;
    private final String OAUTH_HEADER = "Bearer";
    private final String CONSUMER_KEY = "consumer-key";
    private final String SERVICE_PROVIDER_NAME = "serviceProvider";
    private final String SERVICE_PROVIDER_TENANT_DOMAIN = "serviceProviderTenantDomain";
    private final String SERVICE_PROVIDER_UUID = "serviceProviderUUID";
    private final String SCIM_ME_ENDPOINT_URI = "scim2/me";
    private final String AUT_APPLICATION = "APPLICATION";
    private final String AUT_APPLICATION_USER = "APPLICATION_USER";
    private List<String> impersonateMyAccountResourceConfigs;

    @Override
    public void init(InitConfig initConfig) {

        impersonateMyAccountResourceConfigs = IdentityConfigParser.getImpersonateMyAccountResourceConfigs();
    }

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
                        .put(Constants.AUTHENTICATION_TYPE, oAuth2IntrospectionResponseDTO.getAut());

                if (!oAuth2IntrospectionResponseDTO.isActive() ||
                        RefreshTokenValidator.TOKEN_TYPE_NAME.equals(oAuth2IntrospectionResponseDTO.getTokenType())) {
                    return authenticationResult;
                }

                boolean isUserSessionImpersonationEnabled = OAuthServerConfiguration.getInstance()
                        .isUserSessionImpersonationEnabled();
                if (isUserSessionImpersonationEnabled) {
                    /* If the token is impersonated access token issued for MY_ACCOUNT, block all the actions excepts
                    for discoverable actions. */
                    boolean isValidOperation = validateAllowedDuringImpersonation(authenticationContext.getResourceConfig(),
                            oAuth2IntrospectionResponseDTO.getScope(),
                            oAuth2IntrospectionResponseDTO.getClientId());
                    if (!isValidOperation) {
                        if (log.isDebugEnabled()) {
                            log.debug("Not an allowed operation during impersonation.");
                        }
                        return authenticationResult;
                    }
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

                handleImpersonatedAccessToken(authenticationContext, accessToken, oAuth2IntrospectionResponseDTO);

                authenticationResult.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
                setActorToIdentityContext(oAuth2IntrospectionResponseDTO);

                User authorizedUser = oAuth2IntrospectionResponseDTO.getAuthorizedUser();
                String authorizedUserTenantDomain = null;
                if (authorizedUser != null) {
                    authenticationContext.setUser(authorizedUser);
                    authorizedUserTenantDomain = authorizedUser.getTenantDomain();
                    if (authorizedUser instanceof AuthenticatedUser) {
                        IdentityUtil.threadLocalProperties.get()
                                .put(Constants.IS_FEDERATED_USER,
                                        ((AuthenticatedUser) authorizedUser).isFederatedUser());
                        IdentityUtil.threadLocalProperties.get()
                                .put(Constants.IDP_NAME, ((AuthenticatedUser) authorizedUser).getFederatedIdPName());
                    } else {
                        AuthenticatedUser authenticatedUser = new AuthenticatedUser(authorizedUser);
                        IdentityUtil.threadLocalProperties.get()
                                .put(Constants.IS_FEDERATED_USER, authenticatedUser.isFederatedUser());
                        IdentityUtil.threadLocalProperties.get()
                                .put(Constants.IDP_NAME, authenticatedUser.getFederatedIdPName());
                    }
                }

                authenticationContext.addParameter(CONSUMER_KEY, oAuth2IntrospectionResponseDTO.getClientId());
                authenticationContext.addParameter(Constants.OAUTH2_ALLOWED_SCOPES,
                        OAuth2Util.buildScopeArray(oAuth2IntrospectionResponseDTO.getScope()));
                authenticationContext.addParameter(Constants.OAUTH2_VALIDATE_SCOPE,
                        AuthConfigurationUtil.getInstance().isScopeValidationEnabled());

                ServiceProvider serviceProvider = null;
                String serviceProviderName = null;
                String serviceProviderUUID = null;
                try {
                    /*
                     Tokens which are issued for the applications which are registered in sub organization,
                     contains the tenant domain for the authorized user as the sub organization. Based on that
                     we can get the application details by using both the client id and the tenant domain.
                    */
                    if (StringUtils.isNotEmpty(authorizedUserTenantDomain) && OrganizationManagementUtil.
                            isOrganization(authorizedUserTenantDomain)) {
                        serviceProvider = OAuth2Util.getServiceProvider(oAuth2IntrospectionResponseDTO.getClientId(),
                                authorizedUserTenantDomain);
                    } else {
                        serviceProvider = OAuth2Util.getServiceProvider(oAuth2IntrospectionResponseDTO.getClientId());
                    }
                    if (serviceProvider != null) {
                        serviceProviderName = serviceProvider.getApplicationName();
                        serviceProviderUUID = serviceProvider.getApplicationResourceId();
                    } else {
                        log.debug("There is no associated Service provider for client Id "
                                + oAuth2IntrospectionResponseDTO.getClientId());
                        throw new IdentityOAuth2Exception("There is no associated Service provider for client Id "
                                + oAuth2IntrospectionResponseDTO.getClientId());
                    }
                } catch (IdentityOAuth2Exception e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Error occurred while getting the Service Provider by Consumer key: "
                                + oAuth2IntrospectionResponseDTO.getClientId(), e);
                    }
                } catch (OrganizationManagementException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Error occurred while checking the tenant domain: " +
                                authorizedUserTenantDomain + " is an organization.", e);
                    }
                }

                /*
                 Set OAuthAppDO to the authentication context to be used when checking the user belongs to the
                 requested tenant. This needs to be executed in the sub organization level.
                */
                OAuthAppDO oAuthAppDO = null;
                try {
                    if (StringUtils.isNotEmpty(authorizedUserTenantDomain) && OrganizationManagementUtil.
                            isOrganization(authorizedUserTenantDomain)) {
                        oAuthAppDO = OAuth2Util.getAppInformationByClientId(
                                oAuth2IntrospectionResponseDTO.getClientId(), authorizedUserTenantDomain);
                    }
                } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Error occurred while getting the OAuth App by Consumer key: "
                                + oAuth2IntrospectionResponseDTO.getClientId() + " and tenant domain: " +
                                authorizedUserTenantDomain, e);
                    }
                } catch (OrganizationManagementException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Error occurred while checking the tenant domain: " +
                                authorizedUserTenantDomain + " is an organization.", e);
                    }
                }
                if (oAuthAppDO != null) {
                    authenticationContext.addParameter(Constants.AUTH_CONTEXT_OAUTH_APP_PROPERTY, oAuthAppDO);
                }

                String serviceProviderTenantDomain = null;
                try {
                    /*
                     Tokens which are issued for the applications which are registered in sub organization,
                     contains the tenant domain for the authorized user as the sub organization. Based on that
                     we can get the application tenant domain detail by using both the client id and the tenant domain.
                    */
                    if (StringUtils.isNotEmpty(authorizedUserTenantDomain) && OrganizationManagementUtil.
                            isOrganization(authorizedUserTenantDomain)) {
                        serviceProviderTenantDomain =
                                OAuth2Util.getTenantDomainOfOauthApp(oAuth2IntrospectionResponseDTO.getClientId(),
                                        authorizedUserTenantDomain);
                    } else {
                        serviceProviderTenantDomain =
                                OAuth2Util.getTenantDomainOfOauthApp(oAuth2IntrospectionResponseDTO.getClientId());
                    }
                } catch (InvalidOAuthClientException | IdentityOAuth2Exception e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Error occurred while getting the OAuth App tenantDomain by Consumer key: "
                                + oAuth2IntrospectionResponseDTO.getClientId(), e);
                    }
                } catch (OrganizationManagementException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Error occurred while checking the tenant domain: " +
                                authorizedUserTenantDomain + " is an organization.", e);
                    }
                }

                if (serviceProviderName != null){
                    authenticationContext.addParameter(SERVICE_PROVIDER_NAME, serviceProviderName);
                    MDC.put(SERVICE_PROVIDER_NAME, serviceProviderName);
                }
                if (serviceProviderTenantDomain != null) {
                    authenticationContext.addParameter(SERVICE_PROVIDER_TENANT_DOMAIN, serviceProviderTenantDomain);
                }
                if (serviceProviderUUID != null) {
                    authenticationContext.addParameter(SERVICE_PROVIDER_UUID, serviceProviderUUID);
                    MDC.put(SERVICE_PROVIDER_UUID, serviceProviderUUID);
                }
                // Set OAuth service provider details to be consumed by the provisioning framework.
                setProvisioningServiceProviderThreadLocal(oAuth2IntrospectionResponseDTO.getClientId(),
                        serviceProviderTenantDomain);
            }
        }
        return authenticationResult;
    }

    /**
     * If the application is MY_ACCOUNT and the token is impersonated allow only
     * allowed operations during impersonation.
     *
     * @param resourceConfig Resource Config.
     * @param allowedScopes  Allowed scopes in the token.
     * @param clientId       Client id.
     * @return Whether the operation is allowed or not.
     */
    private boolean validateAllowedDuringImpersonation(ResourceConfig resourceConfig, String allowedScopes,
                                                       String clientId) {

        List<String> scopes = Arrays.asList(OAuth2Util.buildScopeArray(allowedScopes));
        return !(MY_ACCOUNT_APPLICATION_CLIENT_ID.equals(clientId)
                && scopes.contains(IMPERSONATION_SCOPE_NAME)
                && !GET.equals(resourceConfig.getHttpMethod())
                && impersonateMyAccountResourceConfigs.stream()
                    .noneMatch(resource -> resourceConfig.getContext().contains(resource)));
    }

    private void setActorToIdentityContext(OAuth2IntrospectionResponseDTO introspectionResponseDTO) {

        String authenticatedEntity = introspectionResponseDTO.getAut();
        if (authenticatedEntity == null) {
            return;
        }

        switch (authenticatedEntity) {
            case AUT_APPLICATION:
                ApplicationActor actor = new ApplicationActor.Builder()
                        .authenticationType(ApplicationActor.AuthType.OAUTH2)
                        .entityId(introspectionResponseDTO.getClientId())
                        .build();
                IdentityContext.getThreadLocalIdentityContext().setActor(actor);
                break;
            case AUT_APPLICATION_USER:
                UserActor.Builder userBuilder =  new UserActor.Builder()
                        .username(introspectionResponseDTO.getAuthorizedUser().getUserName());
                try {
                    userBuilder.userId(introspectionResponseDTO.getAuthorizedUser().getUserId());
                } catch (UserIdNotFoundException e) {
                    log.warn("No userId found for the authenticated user.", e);
                }
                IdentityContext.getThreadLocalIdentityContext().setActor(userBuilder.build());
                break;
            default:
                break;
        }
    }

    /**
     * Handles the logging of impersonated access tokens. This method extracts the claims from the given
     * access token and checks if it represents an impersonation request. If impersonation is detected,
     * it logs the impersonation event with relevant details such as subject, impersonator, resource path,
     * HTTP method, client ID, and scope. The method ensures that only non-GET requests are logged for audit purposes.
     *
     * @param authenticationContext The authentication context containing the authentication request details.
     * @param accessToken The access token to be inspected for impersonation.
     * @param introspectionResponseDTO The introspection response containing token details.
     */
    private void handleImpersonatedAccessToken(AuthenticationContext authenticationContext,
                                               String accessToken,
                                               OAuth2IntrospectionResponseDTO introspectionResponseDTO) {

        String subject = null;
        String impersonator = null;
        try {
            if (OAuth2Constants.TokenTypes.JWT.equalsIgnoreCase(introspectionResponseDTO.getTokenType())) {
                // Extract claims from the access token
                SignedJWT signedJWT = getSignedJWT(accessToken);
                JWTClaimsSet claimsSet = getClaimSet(signedJWT);
                if (claimsSet != null) {
                    subject = resolveSubject(claimsSet);
                    impersonator = resolveImpersonator(claimsSet);
                }
            } else {
                // Extract claims from the introspection response.
                if (introspectionResponseDTO.getProperties().containsKey(IMPERSONATING_ACTOR)) {
                    subject = introspectionResponseDTO.getAuthorizedUser().getAuthenticatedSubjectIdentifier();
                    impersonator = (String) introspectionResponseDTO.getProperties().get(IMPERSONATING_ACTOR);
                }
            }

            // Check if the token represents an impersonation request
            if (impersonator != null) {
                MDC.put(Constants.IMPERSONATOR, impersonator);
                String scope = introspectionResponseDTO.getScope();
                String clientId = introspectionResponseDTO.getClientId();
                String requestUri = authenticationContext.getAuthenticationRequest().getRequestUri();
                String httpMethod = authenticationContext.getAuthenticationRequest().getMethod();

                // Ensure it's not a GET request before logging
                if (!GET.equals(httpMethod)) {
                    // Prepare data for audit log
                    JSONObject data = new JSONObject();
                    data.put(Constants.SUBJECT, subject);
                    data.put(Constants.IMPERSONATOR, impersonator);
                    data.put(Constants.RESOURCE_PATH, requestUri);
                    data.put(Constants.HTTP_METHOD, httpMethod);
                    data.put(Constants.CLIENT_ID, clientId);
                    data.put(Constants.SCOPE, scope);

                    String action;

                    switch (httpMethod) {
                        case Constants.PATCH:
                            action = Constants.IMPERSONATION_RESOURCE_MODIFICATION;
                            break;
                        case Constants.POST:
                            action = Constants.IMPERSONATION_RESOURCE_CREATION;
                            break;
                        case Constants.DELETE:
                            action = Constants.IMPERSONATION_RESOURCE_DELETION;
                            break;
                        default:
                            action = Constants.IMPERSONATION_RESOURCE_ACCESS;
                            break;
                    }
                    // Log the audit event
                    AUDIT.info(createAuditMessage(impersonator, action, subject, data, Constants.AUTHORIZED));
                }
            }
        } catch (IdentityOAuth2Exception e) {
            // Ignore IdentityOAuth2Exception since this is an audit log section
        }
    }

    /**
     * To create an audit message based on provided parameters.
     *
     * @param action      Activity
     * @param target      Target affected by this activity.
     * @param data        Information passed along with the request.
     * @param resultField Result value.
     * @return Relevant audit log in Json format.
     */
    private String createAuditMessage(String subject, String action, String target, JSONObject data, String resultField) {

        String auditMessage =
                Constants.INITIATOR + "=%s " + Constants.ACTION + "=%s " + Constants.TARGET + "=%s "
                        + Constants.DATA + "=%s " + Constants.OUTCOME + "=%s";
        return String.format(auditMessage, subject, action, target, data, resultField);
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

    /**
     * Get the SignedJWT by parsing the subjectToken.
     *
     * @param token Token sent in the request
     * @return SignedJWT
     * @throws IdentityOAuth2Exception Error when parsing the subjectToken
     */
    private SignedJWT getSignedJWT(String token) throws IdentityOAuth2Exception {

        SignedJWT signedJWT;
        if (StringUtils.isEmpty(token)) {
            return null;
        }
        try {
            signedJWT = SignedJWT.parse(token);
            return signedJWT;
        } catch (ParseException e) {
            throw new IdentityOAuth2Exception("Error while parsing the JWT", e);
        }
    }

    /**
     * Retrieve the JWTClaimsSet from the SignedJWT.
     *
     * @param signedJWT SignedJWT object
     * @return JWTClaimsSet
     * @throws IdentityOAuth2Exception Error when retrieving the JWTClaimsSet
     */
    public static JWTClaimsSet getClaimSet(SignedJWT signedJWT) throws IdentityOAuth2Exception {

        try {
            if (signedJWT != null){
                return signedJWT.getJWTClaimsSet();
            }
            return null;
        } catch (ParseException e) {
            throw new IdentityOAuth2Exception("Error when retrieving claimsSet from the JWT", e);
        }
    }

    /**
     * The default implementation creates the subject from the Sub attribute.
     * To translate between the federated and local user store, this may need some mapping.
     * Override if needed
     *
     * @param claimsSet all the JWT claims
     * @return The subject, to be used
     */
    private String resolveSubject(JWTClaimsSet claimsSet) {

        return claimsSet.getSubject();
    }

    private String resolveImpersonator(JWTClaimsSet claimsSet) {

        if (claimsSet.getClaim(Constants.ACT) != null) {

            Map<String, String>  mayActClaimSet = (Map) claimsSet.getClaim(Constants.ACT);
            return mayActClaimSet.get(Constants.SUB);
        }
        return null;
    }
}
