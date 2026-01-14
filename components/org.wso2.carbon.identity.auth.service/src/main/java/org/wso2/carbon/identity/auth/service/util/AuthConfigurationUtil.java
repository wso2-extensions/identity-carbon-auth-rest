/*
 * Copyright (c) 2016-2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.auth.service.util;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.context.model.OperationScopeSet;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.auth.service.internal.AuthenticationServiceHolder;
import org.wso2.carbon.identity.auth.service.module.ResourceConfig;
import org.wso2.carbon.identity.auth.service.module.ResourceConfigKey;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.securevault.SecretResolver;
import org.wso2.securevault.SecretResolverFactory;
import org.wso2.securevault.commons.MiscellaneousUtil;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;

import static org.wso2.carbon.identity.auth.service.util.Constants.AUTHORIZATION_CONTROL_ELE;
import static org.wso2.carbon.identity.auth.service.util.Constants.AUTH_HANDLER_ELE;
import static org.wso2.carbon.identity.auth.service.util.Constants.ENDPOINT_LIST_ELE;
import static org.wso2.carbon.identity.auth.service.util.Constants.RESOURCE_OPERATIONS_ELE;
import static org.wso2.carbon.identity.auth.service.util.Constants.RESOURCE_OPERATION_ELE;
import static org.wso2.carbon.identity.auth.service.util.Constants.RESOURCE_OPERATION_ELE_MANDATORY_ATTR;
import static org.wso2.carbon.identity.auth.service.util.Constants.RESOURCE_OPERATION_ELE_NAME_ATTR;
import static org.wso2.carbon.identity.auth.service.util.Constants.RESOURCE_OPERATION_ELE_SCOPE_ATTR;
import static org.wso2.carbon.identity.auth.service.util.Constants.SKIP_AUTHORIZATION_ELE;

public class AuthConfigurationUtil {

    private static AuthConfigurationUtil authConfigurationUtil = new AuthConfigurationUtil();

    private Map<ResourceConfigKey, ResourceConfig> resourceConfigMap = new LinkedHashMap<>();
    private Map<String, String> applicationConfigMap = new HashMap<>();
    private List<String> intermediateCertCNList = new ArrayList<>();
    private List<CertUserMapping> userThumbPrintMappings = new ArrayList<>();
    private List<SystemThumbprintMapping> systemThumbprintMappings = new ArrayList<>();
    private List<String> exemptedContextList = new ArrayList<>();
    private Map<String, String[]> skipAuthorizationAllowedEndpoints = new HashMap<>();
    private boolean isIntermediateCertValidationEnabled = false;
    private boolean isClientCertBasedAuthnEnabled = false;
    private static final String SECRET_ALIAS = "secretAlias";
    private static final String SECRET_ALIAS_NAMESPACE_URI = "http://org.wso2.securevault/configuration";
    private static final String SECRET_ALIAS_PREFIX = "svns";
    private static final String regex = "\\s*,\\s*";
    private static final String TENANT_PERSPECTIVE_REQUEST_REGEX = "^/t/[^/]+/o/[a-f0-9\\-]+?";
    private String defaultAccess;
    private boolean isScopeValidationEnabled = true;

    private static final Log log = LogFactory.getLog(AuthConfigurationUtil.class);

    public static class CertUserMapping {

        private final String certifiedIssuer;
        private final String certThumbprint;
        private final ArrayList<String> allowedUsernames;

        public CertUserMapping(String certifiedIssuer, String certFingerPrint,
                               ArrayList<String> allowedUsernames) {
            this.certifiedIssuer = certifiedIssuer;
            this.certThumbprint = certFingerPrint;
            this.allowedUsernames = allowedUsernames;
        }

        public String getAllowedThumbprint() {
            return certThumbprint;
        }

        public ArrayList<String> getAllowedUsernames() {
            return allowedUsernames;
        }

        public String getAllowedIssuer() {
            return certifiedIssuer;
        }
    }

    public static class SystemThumbprintMapping {

        private final String certThumbprint;
        private final String allowedSystemUser;
        private final String certifiedIssuer;

        public SystemThumbprintMapping(String certifiedIssuer, String certThumbprint, String allowedSystemUser) {
            this.certThumbprint = certThumbprint;
            this.allowedSystemUser = allowedSystemUser;
            this.certifiedIssuer = certifiedIssuer;
        }

        public String getAllowedThumbprint() {
            return certThumbprint;
        }

        public String getAllowedSystemUser() {
            return allowedSystemUser;
        }

        public String getAllowedIssuer() {
            return certifiedIssuer;
        }

    }

    private AuthConfigurationUtil() {
    }

    public static AuthConfigurationUtil getInstance() {
        return AuthConfigurationUtil.authConfigurationUtil;
    }

    public ResourceConfig getSecuredConfig(ResourceConfigKey resourceConfigKey) {
        ResourceConfig resourceConfig = null;
        for (Map.Entry<ResourceConfigKey, ResourceConfig> entry : resourceConfigMap.entrySet()) {
            if (entry.getKey().equals(resourceConfigKey)) {
                resourceConfig = entry.getValue();
                break;
            }
        }
        return resourceConfig;
    }

    /**
     * Build rest api resource control config.
     */
    public void buildResourceAccessControlData() {

        OMElement resourceAccessControl = getResourceAccessControlConfigs();
        if (resourceAccessControl != null) {
            defaultAccess = resourceAccessControl.getAttributeValue(new QName(Constants.RESOURCE_DEFAULT_ACCESS));
            isScopeValidationEnabled = !Boolean.parseBoolean(resourceAccessControl
                    .getAttributeValue(new QName(Constants.RESOURCE_DISABLE_SCOPE_VALIDATION)));
            Iterator<OMElement> resources = resourceAccessControl.getChildrenWithName(
                    new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, Constants.RESOURCE_ELE));
            if ( resources != null ) {

                while (resources.hasNext()) {
                    OMElement resource = resources.next();
                    ResourceConfig resourceConfig = new ResourceConfig();
                    String httpMethod = resource.getAttributeValue(
                            new QName(Constants.RESOURCE_HTTP_METHOD_ATTR));
                    String context = resource.getAttributeValue(new QName(Constants.RESOURCE_CONTEXT_ATTR));
                    String isSecured = resource.getAttributeValue(new QName(Constants.RESOURCE_SECURED_ATTR));
                    String isCrossTenantAllowed = resource.getAttributeValue(new QName(Constants.RESOURCE_CROSS_TENANT_ATTR));
                    String allowedAuthHandlers =
                            resource.getAttributeValue(new QName(Constants.RESOURCE_ALLOWED_AUTH_HANDLERS));

                    StringBuilder permissionBuilder = new StringBuilder();
                    Iterator<OMElement> permissionsIterator = resource.getChildrenWithName(
                            new QName(Constants.RESOURCE_PERMISSION_ELE));
                    if ( permissionsIterator != null ) {
                        while ( permissionsIterator.hasNext() ) {
                            OMElement permissionElement = permissionsIterator.next();
                            String permission = permissionElement.getText();
                            if ( StringUtils.isNotEmpty(permissionBuilder.toString()) &&
                                    StringUtils.isNotEmpty(permission) ) {
                                permissionBuilder.append(",");
                            }
                            if ( StringUtils.isNotEmpty(permission) ) {
                                permissionBuilder.append(permission);
                            }
                        }
                    }

                    List<String> scopes = new ArrayList<>();
                    Iterator<OMElement> scopesIterator = resource.getChildrenWithName(
                            new QName(Constants.RESOURCE_SCOPE_ELE));
                    if (scopesIterator != null) {
                        while (scopesIterator.hasNext()) {
                            OMElement scopeElement = scopesIterator.next();
                            scopes.add(scopeElement.getText());
                        }
                    }

                    resourceConfig.setContext(context);
                    resourceConfig.setHttpMethod(httpMethod);
                    if ( StringUtils.isNotEmpty(isSecured) && (Boolean.TRUE.toString().equals(isSecured) ||
                            Boolean.FALSE.toString().equals(isSecured)) ) {
                        resourceConfig.setIsSecured(Boolean.parseBoolean(isSecured));
                    }
                    String crossAccessAllowedTenants =
                            resource.getAttributeValue(new QName(Constants.RESOURCE_CROSS_ACCESS_ALLOWED_TENANTS));

                    if (StringUtils.isNotEmpty(isCrossTenantAllowed) &&
                            (Boolean.TRUE.toString().equals(isCrossTenantAllowed)
                                    || Boolean.FALSE.toString().equals(isCrossTenantAllowed))) {
                        resourceConfig.setIsCrossTenantAllowed(Boolean.parseBoolean(isCrossTenantAllowed));
                        if (resourceConfig.isCrossTenantAllowed() &&
                                StringUtils.isNotEmpty(crossAccessAllowedTenants)) {
                            resourceConfig.setCrossAccessAllowedTenants(buildCrossAccessAllowedTenants
                                    (crossAccessAllowedTenants));
                        }
                    }

                    if (StringUtils.isBlank(allowedAuthHandlers)) {
                        // If 'allowed-auth-handlers' is not configured we consider all handlers are engaged.
                        allowedAuthHandlers = Constants.RESOURCE_ALLOWED_AUTH_HANDLERS_ALL;
                    }
                    resourceConfig.setAllowedAuthHandlers(allowedAuthHandlers);
                    resourceConfig.setPermissions(permissionBuilder.toString());
                    resourceConfig.setScopes(scopes);

                    // Parse <Operations> if present
                    Iterator<OMElement> operationsElementItr = resource.getChildrenWithName(
                            new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, RESOURCE_OPERATIONS_ELE));

                    if (operationsElementItr != null && operationsElementItr.hasNext()) {
                        OMElement operationsElement = operationsElementItr.next();  // There should be only one <Operations> per <Resource>
                        boolean isMandatory =
                                Boolean.parseBoolean(operationsElement.getAttributeValue(new QName(RESOURCE_OPERATION_ELE_MANDATORY_ATTR)));
                        Iterator<OMElement> operationElements = operationsElement.getChildrenWithName(
                                new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, RESOURCE_OPERATION_ELE));

                        OperationScopeSet operationScopeSet = new OperationScopeSet();
                        operationScopeSet.setIsMandatory(isMandatory);
                        Map<String, String> operationScopeMap = new HashMap<>();
                        while (operationElements.hasNext()) {
                            OMElement operationElement = operationElements.next();
                            String operationName = operationElement.getAttributeValue(new QName(
                                    RESOURCE_OPERATION_ELE_NAME_ATTR));
                            OMElement scopeElement = operationElement.getFirstChildWithName(new QName(
                                    IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE,
                                    RESOURCE_OPERATION_ELE_SCOPE_ATTR));

                            if (StringUtils.isNotBlank(operationName) && scopeElement != null &&
                                    StringUtils.isNotBlank(scopeElement.getText())) {
                                operationScopeMap.put(operationName, scopeElement.getText());
                            }
                        }
                        if (!operationScopeMap.isEmpty()) {
                            operationScopeSet.setOperationScopeMap(operationScopeMap);
                            resourceConfig.setOperationScopeSet(operationScopeSet);
                        }
                    }

                    ResourceConfigKey resourceConfigKey = new ResourceConfigKey(context, httpMethod);
                    if (!resourceConfigMap.containsKey(resourceConfigKey)) {
                        resourceConfigMap.put(resourceConfigKey, resourceConfig);
                    }
                }
            }
        }
    }

    private static OMElement getResourceAccessControlConfigs() {

        /*
        Check whether legacy authorization runtime is enabled.
        Use the legacy resource access control configs if enabled.
        */
        if (CarbonConstants.ENABLE_LEGACY_AUTHZ_RUNTIME) {
            return IdentityConfigParser.getInstance().getConfigElement(Constants
                    .RESOURCE_ACCESS_CONTROL_ELE);
        }
        Path path = Paths.get(IdentityUtil.getIdentityConfigDirPath(), Constants.RESOURCE_ACCESS_CONTROL_V2_FILE);
        if (Files.exists(path)) {
            try (InputStream in = Files.newInputStream(path)) {
                StAXOMBuilder builder = new StAXOMBuilder(in);
                return builder.getDocumentElement().cloneOMElement();
            } catch (IOException e) {
                String message = "Error while reading Resource Access control configuration at: " + path.getFileName();
                log.error(message);
            } catch (XMLStreamException e) {
                String message = "Error while parsing Resource Access control configuration at: " + path.getFileName();
                log.error(message);
            }
        } else {
            log.error("Resource Access control configuration not found at: " + path.getFileName());
        }
        return null;
    }

    public List<String> buildAllowedAuthenticationHandlers(String allowedAuthenticationHandlers) {

        List<String> allowedAuthHandlersList = new ArrayList<>();
        if (StringUtils.equals(allowedAuthenticationHandlers, Constants.RESOURCE_ALLOWED_AUTH_HANDLERS_ALL)) {
            List<AuthenticationHandler> allAvailableAuthHandlers =
                    AuthenticationServiceHolder.getInstance().getAuthenticationHandlers();
            for (AuthenticationHandler handler : allAvailableAuthHandlers) {
                String handlerName = handler.getName();
                if (Constants.BASIC_CLIENT_AUTH_HANDLER.equals(handlerName)) {
                    continue;
                }
                allowedAuthHandlersList.add(handlerName);
            }
        } else {
            String[] allowedAuthHandlerNames = allowedAuthenticationHandlers.split(regex);
            allowedAuthHandlersList.addAll(Arrays.asList(allowedAuthHandlerNames));
        }
        return allowedAuthHandlersList;
    }

    /**
     * Build rest api resource control config.
     */
    public void buildClientAuthenticationHandlerControlData() {

        OMElement resourceAccessControl = IdentityConfigParser.getInstance().getConfigElement(Constants
                .CLIENT_APP_AUTHENTICATION_ELE);
        if (resourceAccessControl != null) {

            Iterator<OMElement> applications = resourceAccessControl.getChildrenWithName(
                    new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, Constants.APPLICATION_ELE));
            if (applications != null) {
                while (applications.hasNext()) {
                    OMElement resource = applications.next();
                    SecretResolver secretResolver = SecretResolverFactory.create(resource, true);
                    String appName = resource.getAttributeValue(new QName(Constants.APPLICATION_NAME_ATTR));
                    String hash = resource.getAttributeValue(new QName(Constants.APPLICATION_HASH_ATTR));
                    String secretAlias = resource.getAttributeValue
                            (new QName(SECRET_ALIAS_NAMESPACE_URI, SECRET_ALIAS, SECRET_ALIAS_PREFIX));
                    if (StringUtils.isNotBlank(secretAlias)) {
                        hash = MiscellaneousUtil.resolve(secretAlias, secretResolver);
                    } else {
                        hash = MiscellaneousUtil.resolve(hash, secretResolver);
                    }
                    applicationConfigMap.put(appName, hash);
                }
            }
        }
    }

    /**
     * Build cert based authentication enabled config.
     */
    public void buildClientCertBasedAuthnEnabled() {

        OMElement root = IdentityConfigParser.getInstance()
                .getConfigElement(Constants.CERT_BASED_AUTHENTICATION_ELE);

        if (root != null) {
            isClientCertBasedAuthnEnabled = Boolean.parseBoolean(
                    root.getAttributeValue(new QName(Constants.CERT_AUTHENTICATION_ENABLE_ATTR)));
        }
        if (!isClientCertBasedAuthnEnabled) {
            return;
        }

        OMElement userMappingsEle = root.getFirstChildWithName(
                new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, Constants.USER_THUMBPRINT_MAPPINGS));
        if (userMappingsEle != null) {
            Iterator<OMElement> items = userMappingsEle.getChildrenWithName(
                    new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, Constants.MAPPING));
            while (items != null && items.hasNext()) {
                OMElement m = items.next();

                String trustedIssuer = getChildText(m, Constants.TRUSTED_ISSUER_ELE);
                if (StringUtils.isEmpty(trustedIssuer)) {
                    log.warn("Skipping user mapping. Missing 'trusted_issuer'.");
                    continue;
                }

                if (Constants.WILDCARD.equals(trustedIssuer)) {
                    log.warn("Skipping user thumbprint mapping. 'trusted_issuer' cannot be '*'.");
                    continue;
                }

                String certThumbprint = getChildText(m, Constants.CERT_THUMBPRINT);
                if (StringUtils.isEmpty(certThumbprint)) {
                    certThumbprint = Constants.WILDCARD;
                }

                ArrayList<String> allowedUsers = new ArrayList<>(
                        getChildrenTextList(m, Constants.ALLOWED_USERNAME, true)
                );
                if (allowedUsers.isEmpty()) {
                    allowedUsers.add(Constants.WILDCARD);
                }

                userThumbPrintMappings.add(
                        new CertUserMapping(
                                trustedIssuer,
                                certThumbprint,
                                allowedUsers
                        )
                );
            }
        }

        OMElement systemMappingsEle = root.getFirstChildWithName(
                new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, Constants.SYSTEM_THUMBPRINT_MAPPINGS));
        if (systemMappingsEle != null) {
            Iterator<OMElement> items = systemMappingsEle.getChildrenWithName(
                    new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, Constants.MAPPING));
            while (items != null && items.hasNext()) {
                OMElement m = items.next();

                String trustedIssuer = getChildText(m, Constants.TRUSTED_ISSUER_ELE);
                if (StringUtils.isEmpty(trustedIssuer)) {
                    log.warn("Skipping system thumbprint mapping. Missing 'trusted_issuer'.");
                    continue;
                }

                if (Constants.WILDCARD.equals(trustedIssuer)) {
                    log.warn("Skipping system thumbprint mapping. 'trusted_issuer' cannot be '*'.");
                    continue;
                }

                String certThumbPrint = getChildText(m, Constants.CERT_THUMBPRINT);
                if (StringUtils.isEmpty(certThumbPrint)) {
                    certThumbPrint = Constants.WILDCARD;
                }

                String sysUser = getChildText(m, Constants.ALLOWED_SYSTEM_USER);
                if (StringUtils.isEmpty(sysUser)) {
                    sysUser = Constants.WILDCARD;
                }

                systemThumbprintMappings.add(
                        new SystemThumbprintMapping(
                                trustedIssuer,
                                certThumbPrint,
                                sysUser
                        )
                );
            }
        }
    }

    /**
     * Build intermediate cert validation config.
     */
    public void buildIntermediateCertValidationConfigData() {

        OMElement intermediateCertValidationElement = IdentityConfigParser.getInstance().getConfigElement(Constants
                .INTERMEDIATE_CERT_VALIDATION_ELE);
        if (intermediateCertValidationElement != null) {
            isIntermediateCertValidationEnabled = Boolean.parseBoolean(intermediateCertValidationElement
                    .getAttributeValue(new QName(Constants.CERT_AUTHENTICATION_ENABLE_ATTR)));
            if (isIntermediateCertValidationEnabled) {
                // Get intermediate cert CNs.
                OMElement intermediateCertsElement = intermediateCertValidationElement.getFirstChildWithName(
                        new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, Constants.INTERMEDIATE_CERTS_ELE));
                Iterator<OMElement> certs = intermediateCertsElement.getChildrenWithName(
                        new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, Constants.CERT_CN_ELE));
                if (certs != null) {
                    while (certs.hasNext()) {
                        OMElement certCNElement = certs.next();
                        intermediateCertCNList.add(certCNElement.getText());
                    }
                }
                // Get exempted context paths from intermediate cert validation.
                OMElement exemptContextElement = intermediateCertValidationElement.getFirstChildWithName(
                        new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, Constants.EXEMPT_CONTEXT_ELE));
                Iterator<OMElement> contexts = exemptContextElement.getChildrenWithName(
                        new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, Constants.CONTEXT_ELE));
                if (contexts != null) {
                    while (contexts.hasNext()) {
                        OMElement contextElement = contexts.next();
                        exemptedContextList.add(contextElement.getText());
                    }
                }
            }
        }
    }

    /**
     * Build cross-tenant-access allowed domains by splitting the crossAccessAllowedTenants string.
     *
     * @param crossAccessAllowedTenants crossAccessAllowedTenants.
     * @return List of crossAccessAllowedTenants.
     */
    private List<String> buildCrossAccessAllowedTenants(String crossAccessAllowedTenants) {

        if (StringUtils.isNotBlank(crossAccessAllowedTenants)) {
            List<String> allowedTenantDomainsList = new ArrayList<>();
            String regex = "\\s*,\\s*";
            String[] allowedTenantDomainsNames = crossAccessAllowedTenants.split(regex);
            allowedTenantDomainsList.addAll(Arrays.asList(allowedTenantDomainsNames));
            return allowedTenantDomainsList;
        }
        return null;
    }

    public String getClientAuthenticationHash(String appName) {
        return applicationConfigMap.get(appName);
    }


    public String getNormalizedRequestURI(String requestURI) throws URISyntaxException, UnsupportedEncodingException {

        if (requestURI == null) {
            return null;
        }

        // Decode once
        String decodedUri = URLDecoder.decode(requestURI, StandardCharsets.UTF_8.name());

        // If the decoded URI still contains '%', consider it unsafe
        if (decodedUri.contains("%")) {
            throw new UnsupportedEncodingException("URL is still encoded or contains invalid encoding after decoding: "
                    + decodedUri);
        }

        // Normalize and return safe URI
        return new URI(decodedUri).normalize().toString();
    }

    public boolean isIntermediateCertValidationEnabled() {

        return isIntermediateCertValidationEnabled;
    }

    public boolean IsClientCertBasedAuthnEnabled() {

        return isClientCertBasedAuthnEnabled;
    }

    public List<CertUserMapping> getCertUserMappings() {
        return userThumbPrintMappings;
    }

    public List<SystemThumbprintMapping> getSystemUserThumbprintMappings() {
        return systemThumbprintMappings;
    }

    public List<String> getIntermediateCertCNList() {

        return intermediateCertCNList;
    }

    public List<String> getExemptedContextList() {

        return exemptedContextList;
    }

    public String getDefaultAccess() {

        return defaultAccess;
    }

    /**
     * Check whether scope validation is enabled for internal resources.
     *
     * @return True if enabled.
     */
    public boolean isScopeValidationEnabled() {

        if (log.isDebugEnabled()) {
            if (isScopeValidationEnabled) {
                log.debug("Scope validation for internal resources is enabled.");
            } else {
                log.debug("Scope validation for internal resources is disabled.");
            }
        }
        return isScopeValidationEnabled;
    }

    /**
     * Check if the authorization header is matching to the provided auth header identifier.
     *
     * @param messageContext       Authentication message context.
     * @param authHeaderIdentifier Specific header identifier to be matched.
     * @return True if matched, false otherwise.
     * @deprecated use {@link #isAuthHeaderMatch(MessageContext, String, boolean)} instead.
     */
    @Deprecated
    public static boolean isAuthHeaderMatch(MessageContext messageContext, String authHeaderIdentifier) {

        return isAuthHeaderMatch(messageContext, authHeaderIdentifier, true);
    }

    /**
     * Check if the authorization header is matching to the provided auth header identifier.
     *
     * @param messageContext       Authentication message context.
     * @param authHeaderIdentifier Specific header identifier to be matched.
     * @param isCaseSensitive      Whether the comparison of the authHeaderIdentifier and the header in the request
     *                             should be case sensitive.
     * @return True if matched, false otherwise.
     */
    public static boolean isAuthHeaderMatch(MessageContext messageContext, String authHeaderIdentifier,
                                            boolean isCaseSensitive) {

        if (messageContext instanceof AuthenticationContext) {
            AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;
            if (authenticationContext.getAuthenticationRequest() != null) {
                String authorizationHeader = authenticationContext.getAuthenticationRequest().
                        getHeader(HttpHeaders.AUTHORIZATION);
                if (StringUtils.isBlank(authorizationHeader)) {
                    return false;
                }
                String[] splitAuthorizationHeader = authorizationHeader.split(" ");
                if (isCaseSensitive) {
                    return splitAuthorizationHeader.length > 0 &&
                            StringUtils.isNotEmpty(splitAuthorizationHeader[0]) &&
                            authHeaderIdentifier.equals(splitAuthorizationHeader[0]);
                } else {
                    // Case insensitive comparison.
                    if (splitAuthorizationHeader.length > 0 && StringUtils.isNotEmpty(splitAuthorizationHeader[0])) {
                        return authHeaderIdentifier.equalsIgnoreCase(splitAuthorizationHeader[0]);
                    }
                }
            }
        }
        return false;
    }

    /**
     * Build configurations of endpoints which are allowed to skip authorization with particular auth handler.
     */
    public void buildSkipAuthorizationAllowedEndpointsData() {

        OMElement skipAuthorizationConfig = IdentityConfigParser.getInstance().getConfigElement(
                AUTHORIZATION_CONTROL_ELE);
        if (skipAuthorizationConfig != null) {
            Iterator<OMElement> configs = skipAuthorizationConfig.getChildrenWithName(
                    new QName(SKIP_AUTHORIZATION_ELE));
            if (configs != null) {
                while (configs.hasNext()) {
                    OMElement config = configs.next();
                    String authHandlerName = config.getAttributeValue(new QName(AUTH_HANDLER_ELE));
                    String[] allowedEndpoints = config.getAttributeValue(
                            new QName(ENDPOINT_LIST_ELE)).split(regex);
                    skipAuthorizationAllowedEndpoints.put(authHandlerName, allowedEndpoints);
                }
            }
        }
    }

    /**
     * Retrieve Map of endpoint that allowed to skip authorization against the auth handler.
     *
     * @return Map of allowed endpoints and auth handler
     */
    public Map<String, String[]> getSkipAuthorizationAllowedEndpoints() {
        return skipAuthorizationAllowedEndpoints;
    }

    /**
     * Retrieve the resource resident tenant domain from the tenant perspective request.
     *
     * @param requestURI tenant perspective request.
     * @return tenant domain of the resource resident tenant.
     */
    public static String getResourceResidentTenantForTenantPerspective(String requestURI) {

        Pattern patternTenantPerspective = Pattern.compile(TENANT_PERSPECTIVE_REQUEST_REGEX);
        if (patternTenantPerspective.matcher(requestURI).find()) {
            int startIndex = requestURI.indexOf("/o/") + 3;
            int endIndex = requestURI.indexOf("/", startIndex);
            String resourceOrgId = requestURI.substring(startIndex, endIndex);
            try {
                return AuthenticationServiceHolder.getInstance().getOrganizationManager().
                        resolveTenantDomain(resourceOrgId);
            } catch (OrganizationManagementException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Failed to resolve tenant for resourceOrgId: " + resourceOrgId, e);
                }
            }
        }
        return null;
    }

    private static QName qn(String local) {

        return new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, local);
    }

    private static String getChildText(OMElement parent, String local) {

        OMElement child = parent.getFirstChildWithName(qn(local));
        return child != null ? StringUtils.trim(child.getText()) : null;
    }

    private static String safeText(OMElement ele) {

        return ele == null ? null : StringUtils.trimToNull(ele.getText());
    }

    private static List<String> getChildrenTextList(OMElement parent, String childLocalName, boolean dedupe) {

        ArrayList<String> out = new ArrayList<>();
        if (parent == null) return out;
        Iterator<OMElement> kids = parent.getChildrenWithName(
                new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, childLocalName));
        while (kids != null && kids.hasNext()) {
            String v = safeText(kids.next());
            if (StringUtils.isNotEmpty(v)) out.add(v);
        }
        if (dedupe && !out.isEmpty()) {
            LinkedHashSet<String> set = new LinkedHashSet<>(out);
            out.clear();
            out.addAll(set);
        }
        return out;
    }
}
