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

package org.wso2.carbon.identity.auth.valve;

import com.google.gson.JsonObject;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.slf4j.MDC;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationManager;
import org.wso2.carbon.identity.auth.service.AuthenticationRequest;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.auth.service.exception.AuthClientException;
import org.wso2.carbon.identity.auth.service.exception.AuthRuntimeException;
import org.wso2.carbon.identity.auth.service.exception.AuthServerException;
import org.wso2.carbon.identity.auth.service.exception.AuthenticationFailException;
import org.wso2.carbon.identity.auth.service.exception.AuthenticationFailServerException;
import org.wso2.carbon.identity.auth.service.module.ResourceConfig;
import org.wso2.carbon.identity.auth.service.module.ResourceConfigKey;
import org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil;
import org.wso2.carbon.identity.auth.service.util.Constants;
import org.wso2.carbon.identity.auth.valve.internal.AuthenticationValveDataHolder;
import org.wso2.carbon.identity.auth.valve.internal.AuthenticationValveServiceHolder;
import org.wso2.carbon.identity.auth.valve.util.APIErrorResponseHandler;
import org.wso2.carbon.identity.auth.valve.util.AuthHandlerManager;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.tenant.TenantManager;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import java.net.URISyntaxException;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.auth.service.util.Constants.AUTHENTICATED_WITH_BASIC_AUTH;

/**
 * AuthenticationValve can be used to intercept any request.
 */
public class AuthenticationValve extends ValveBase {

    private static final String AUTH_CONTEXT = "auth-context";
    private static final String USER_AGENT = "User-Agent";
    private static final String REMOTE_ADDRESS = "remoteAddress";
    private static final String SERVICE_PROVIDER = "serviceProvider";
    private final String CLIENT_COMPONENT = "clientComponent";
    private final String REST_API_CLIENT_COMPONENT = "REST API";
    private static final String AUTH_USER_TENANT_DOMAIN = "authUserTenantDomain";
    private final String SERVICE_PROVIDER_TENANT_DOMAIN = "serviceProviderTenantDomain";
    private static final String X_FORWARDED_USER_AGENT = "X-Forwarded-User-Agent";
    private final String CONFIG_CONTEXTUAL_PARAM = "LoggableContextualParams.contextual_param";
    private final String CONFIG_LOG_PARAM_USER_AGENT = "user_agent";
    private final String CONFIG_LOG_PARAM_REMOTE_ADDRESS = "remote_address";
    private static final String URL_PATH_FILTER_REGEX = "(.*)/((\\.+)|(.*;+.*)|%2e)/(.*)";
    private static final Pattern URL_MATCHING_PATTERN = Pattern.compile(URL_PATH_FILTER_REGEX);

    private static final Log log = LogFactory.getLog(AuthenticationValve.class);

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {

        AuthenticationContext authenticationContext = null;
        AuthenticationResult authenticationResult = null;
        String tenantDomain = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        if (!validateTenantDomain(request, response, tenantDomain)) {
            return;
        }
        AuthenticationManager authenticationManager = AuthHandlerManager.getInstance().getAuthenticationManager();
        try {
            validateRequestURI(request.getRequestURI());
            String normalizedRequestURI = AuthConfigurationUtil.getInstance().getNormalizedRequestURI(request.getRequestURI());
            ResourceConfig securedResource = authenticationManager.getSecuredResource(
                    new ResourceConfigKey(normalizedRequestURI, request.getMethod()));


            setRemoteAddressAndUserAgentToMDC(request);

            if (isUnauthorized(securedResource)) {
                APIErrorResponseHandler.handleErrorResponse(null, response,
                        HttpServletResponse.SC_UNAUTHORIZED, null);
                return;
            }

            if (securedResource == null || !securedResource.isSecured()) {
                getNext().invoke(request, response);
                return;
            }

            if (log.isDebugEnabled()) {
                log.debug("AuthenticationValve hit on secured resource : " + request.getRequestURI());
            }
            AuthenticationRequest.AuthenticationRequestBuilder authenticationRequestBuilder = AuthHandlerManager
                    .getInstance().getRequestBuilder(request, response).createRequestBuilder(request, response);
            authenticationContext = new AuthenticationContext(authenticationRequestBuilder.build());
            authenticationContext.setResourceConfig(securedResource);
            //Do authentication.
            authenticationResult = authenticationManager.authenticate(authenticationContext);

            AuthenticationStatus authenticationStatus = authenticationResult.getAuthenticationStatus();
            if (authenticationStatus.equals(AuthenticationStatus.SUCCESS)) {
                // Set service provider info used in authentication if any.
                setThreadLocalServiceProvider(authenticationContext);
                // Set authenticated user tenant domain.
                setThreadLocalAuthUserTenantDomain(authenticationContext);
                // Set client component in to MDC.
                setClientComponent();
                //Set the User object as an attribute for further references.
                request.setAttribute(AUTH_CONTEXT, authenticationContext);
                getNext().invoke(request, response);
            } else {
                APIErrorResponseHandler.handleErrorResponse(authenticationContext, response,
                        HttpServletResponse.SC_UNAUTHORIZED, null);
            }
        } catch (AuthClientException e) {
            APIErrorResponseHandler.handleErrorResponse(authenticationContext, response,
                    HttpServletResponse.SC_BAD_REQUEST, e);
        } catch (AuthServerException e) {
            log.error("Auth Server Exception occurred in Authentication valve :", e);
            APIErrorResponseHandler.handleErrorResponse(authenticationContext, response,
                    HttpServletResponse.SC_BAD_REQUEST, e);
        } catch (AuthenticationFailServerException e) {
            APIErrorResponseHandler.handleErrorResponse(authenticationContext, response,
                    HttpServletResponse.SC_SERVICE_UNAVAILABLE, e);
        } catch (AuthenticationFailException e) {
            APIErrorResponseHandler.handleErrorResponse(authenticationContext, response,
                    HttpServletResponse.SC_UNAUTHORIZED, e);
        } catch (AuthRuntimeException e) {
            log.error("Auth Runtime Exception occurred in Authentication valve :", e);
            APIErrorResponseHandler.handleErrorResponse(authenticationContext, response,
                    HttpServletResponse.SC_UNAUTHORIZED, e);
        } catch (IdentityRuntimeException e) {
            log.error("Identity Runtime Exception occurred in Authentication valve :", e);
            APIErrorResponseHandler.handleErrorResponse(authenticationContext, response,
                    HttpServletResponse.SC_SERVICE_UNAVAILABLE, null);
        } catch (URISyntaxException e) {
            log.debug("Invalid URI syntax of the request :", e);
            APIErrorResponseHandler.handleErrorResponse(null, response, HttpServletResponse.SC_BAD_REQUEST, null);
        } catch (PatternSyntaxException e) {
            log.debug("Invalid pattern syntax of the request :", e);
            APIErrorResponseHandler.handleErrorResponse(null, response, HttpServletResponse.SC_BAD_REQUEST, null);
        } finally {
            // Clear 'IdentityError' thread local.
            if (IdentityUtil.getIdentityErrorMsg() != null) {
                IdentityUtil.clearIdentityErrorMsg();
            }

            // Clear thread local service provider info.
            unsetThreadLocalServiceProvider();
            // Clear thread local current session id.
            unsetCurrentSessionIdThreadLocal();
            // Clear thread local authenticated user tenant domain.
            unsetThreadLocalAuthUserTenantDomain();
            // Clear thread local current access token id.
            unsetCurrentTokenIdThreadLocal();
            // Clear thread local provisioning service provider.
            IdentityApplicationManagementUtil.resetThreadLocalProvisioningServiceProvider();
            // Clear Thread Locals from MDC.
            unsetMDCThreadLocals();
            // Clear thread local authenticated with basic auth flag.
            unsetAuthenticatedWithBasicAuth();
        }


    }

    private void setRemoteAddressAndUserAgentToMDC(Request request) {

        String userAgent = request.getHeader(USER_AGENT);
        String forwardedUserAgent = request.getHeader(X_FORWARDED_USER_AGENT);
        if (StringUtils.isNotEmpty(forwardedUserAgent)) {
            userAgent = forwardedUserAgent;
        }
        String remoteAddr = request.getRemoteAddr();
        if (StringUtils.isNotEmpty(userAgent) && isLoggableParam(CONFIG_LOG_PARAM_USER_AGENT)) {
            MDC.put(USER_AGENT, userAgent);
        }
        if (StringUtils.isNotEmpty(remoteAddr) && isLoggableParam(CONFIG_LOG_PARAM_REMOTE_ADDRESS)) {
            MDC.put(REMOTE_ADDRESS, remoteAddr);
        }
    }

    private boolean isUnauthorized(ResourceConfig securedResource) {

        String defaultAccess = AuthConfigurationUtil.getInstance().getDefaultAccess();
        return Constants.DENY_DEFAULT_ACCESS.equalsIgnoreCase(defaultAccess) && securedResource == null;
    }

    private void setThreadLocalServiceProvider(AuthenticationContext authenticationContext) {

        Object serviceProvider = authenticationContext.getParameter(SERVICE_PROVIDER);
        Object serviceProviderTenantDomain = authenticationContext.getParameter(SERVICE_PROVIDER_TENANT_DOMAIN);
        if (serviceProvider != null && serviceProviderTenantDomain != null) {
            IdentityUtil.threadLocalProperties.get().put(SERVICE_PROVIDER, serviceProvider);
            IdentityUtil.threadLocalProperties.get().put(SERVICE_PROVIDER_TENANT_DOMAIN, serviceProviderTenantDomain);
        }
    }

    private void unsetThreadLocalServiceProvider() {

        IdentityUtil.threadLocalProperties.get().remove(SERVICE_PROVIDER);
        IdentityUtil.threadLocalProperties.get().remove(SERVICE_PROVIDER_TENANT_DOMAIN);
    }

    private void setThreadLocalAuthUserTenantDomain(AuthenticationContext authenticationContext) {

        if (authenticationContext.getUser() != null) {
            IdentityUtil.threadLocalProperties.get().put(AUTH_USER_TENANT_DOMAIN,
                    authenticationContext.getUser().getTenantDomain());
        } else if (log.isDebugEnabled()){
            log.debug("Authenticated user not available to add user tenant domain to thread local property "
                    + AUTH_USER_TENANT_DOMAIN);
        }
    }

    private void unsetThreadLocalAuthUserTenantDomain() {

        IdentityUtil.threadLocalProperties.get().remove(AUTH_USER_TENANT_DOMAIN);
    }

    private void setClientComponent() {

        String serviceProvider = MDC.get(SERVICE_PROVIDER);
        if (serviceProvider != null) {
            MDC.put(CLIENT_COMPONENT, serviceProvider);
        } else {
            MDC.put(CLIENT_COMPONENT, REST_API_CLIENT_COMPONENT);
        }
    }

    private void unsetMDCThreadLocals() {

        MDC.remove(CLIENT_COMPONENT);
        MDC.remove(USER_AGENT);
        MDC.remove(REMOTE_ADDRESS);
        MDC.remove(SERVICE_PROVIDER);
    }

    private boolean isLoggableParam(String param) {

        if (IdentityConfigParser.getInstance() != null) {
            Object configValue = IdentityConfigParser.getInstance().getConfiguration().get(CONFIG_CONTEXTUAL_PARAM);
            List<String> claimsFilters = new ArrayList<>();
            if (configValue instanceof ArrayList) {
                claimsFilters = (ArrayList) configValue;
            } else if (configValue instanceof String) {
                claimsFilters.add((String) configValue);
            }
            return claimsFilters.contains(param);
        }
        return false;
    }

    /**
     * Remove current session id from thread local, which is set in OAuth2AccessTokenHandler.
     */
    private void unsetCurrentSessionIdThreadLocal() {

        if (IdentityUtil.threadLocalProperties.get().get(Constants.CURRENT_SESSION_IDENTIFIER) != null) {
            IdentityUtil.threadLocalProperties.get().remove(Constants.CURRENT_SESSION_IDENTIFIER);
        }
        if (IdentityUtil.threadLocalProperties.get().get(Constants.IS_FEDERATED_USER) != null) {
            IdentityUtil.threadLocalProperties.get().remove(Constants.IS_FEDERATED_USER);
        }
        if (IdentityUtil.threadLocalProperties.get().get(Constants.IDP_NAME) != null) {
            IdentityUtil.threadLocalProperties.get().remove(Constants.IDP_NAME);
        }
    }

    /**
     * Remove current access token id from thread local, which is set in OAuth2AccessTokenHandler.
     */
    private void unsetCurrentTokenIdThreadLocal() {

        if (IdentityUtil.threadLocalProperties.get().get(FrameworkConstants.CURRENT_TOKEN_IDENTIFIER) != null) {
            if (log.isDebugEnabled()) {
                log.debug("Removing the current token identifier from thread local. Token id: "
                        + IdentityUtil.threadLocalProperties.get().get(FrameworkConstants.CURRENT_TOKEN_IDENTIFIER));
            }
            IdentityUtil.threadLocalProperties.get().remove(FrameworkConstants.CURRENT_TOKEN_IDENTIFIER);
        }
    }

    private boolean validateTenantDomain(Request request, Response response, String tenantDomain)
            throws IOException, ServletException {

        try {
            TenantManager tenantManager = AuthenticationValveServiceHolder.getInstance().getRealmService()
                    .getTenantManager();
            if (tenantDomain == null) {
                String errorMsg = "Can't invoke a request to this path.";
                handleInvalidTenantDomainErrorResponse(request, response, HttpServletResponse.SC_NOT_FOUND, errorMsg,
                        null);
                return false;
            }
            else if (!tenantManager.isTenantActive(IdentityTenantUtil.getTenantId(tenantDomain))) {
                String errorMsg = tenantDomain + " is an invalid tenant domain";
                handleInvalidTenantDomainErrorResponse(request, response, HttpServletResponse.SC_NOT_FOUND, errorMsg,
                        tenantDomain);
                return false;
            }
        } catch (UserStoreException ex) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while validating tenant domain.", ex);
            }
            String errorMsg = tenantDomain + " is an invalid tenant domain";
            handleInvalidTenantDomainErrorResponse(request, response, HttpServletResponse.SC_NOT_FOUND, errorMsg,
                    tenantDomain);
            return false;
        } catch (IdentityRuntimeException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while validating tenant domain.", e);
            }
            String INVALID_TENANT_DOMAIN = "Invalid tenant domain";
            if (!StringUtils.isBlank(e.getMessage()) && e.getMessage().contains(INVALID_TENANT_DOMAIN)) {
                String errorMsg = tenantDomain + " is an invalid tenant domain";
                handleInvalidTenantDomainErrorResponse(request, response, HttpServletResponse.SC_NOT_FOUND, errorMsg,
                        tenantDomain);
            } else {
                String errorMsg = "Error occurred while validating tenant domain " + tenantDomain;
                handleInvalidTenantDomainErrorResponse(request, response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        errorMsg, tenantDomain);
            }
            return false;
        }
        return true;
    }

    private void handleInvalidTenantDomainErrorResponse(Request request, Response response, int error, String errorMsg,
                                                        String tenantDomain) throws
            IOException {

        String requestContentType = request.getContentType();
        response.setStatus(error);
        response.setCharacterEncoding("UTF-8");
        if (StringUtils.contains(requestContentType, "application/json")) {
            response.setContentType("application/json");
            JsonObject errorResponse = new JsonObject();
            errorResponse.addProperty("code", error);
            errorResponse.addProperty("message", errorMsg);
            errorResponse.addProperty("description", errorMsg);
            response.getWriter().print(errorResponse.toString());
        } else {
            response.setContentType("text/html");
            String errorPage = AuthenticationValveDataHolder.getInstance().getInvalidTenantDomainErrorPage();
            if (StringUtils.isEmpty(errorPage)) {
                errorPage = readDefaultErrorFromResource("default_error_page_of_invalid_tenant_domain_response.html",
                        this.getClass());
            }
            errorPage = errorPage.replace("$error.msg", errorMsg);
            response.getWriter().print(errorPage);
        }
    }

    private String readDefaultErrorFromResource(String filename, Class cClass) throws IOException {

        try (InputStream resourceAsStream = cClass.getResourceAsStream(filename);
             BufferedInputStream bufferedInputStream = new BufferedInputStream(resourceAsStream)) {
            StringBuilder resourceFile = new StringBuilder();
            int character;
            while ((character = bufferedInputStream.read()) != -1) {
                char value = (char) character;
                resourceFile.append(value);
            }
            return resourceFile.toString();
        }
    }

    /**
     * Remove AUTHENTICATED_WITH_BASIC_AUTH flag, which is set in BasicAuthenticationHandler
     */
    private void unsetAuthenticatedWithBasicAuth() {

        if (IdentityUtil.threadLocalProperties.get() != null) {
            IdentityUtil.threadLocalProperties.get().remove(AUTHENTICATED_WITH_BASIC_AUTH);
        }
    }


    private void validateRequestURI(String url) throws AuthenticationFailException {

        if (url != null && URL_MATCHING_PATTERN.matcher(url).matches()) {
            throw new AuthenticationFailException("Given URL contain un-normalized content. URL validation failed for "
                    + url);
        }
    }
}
