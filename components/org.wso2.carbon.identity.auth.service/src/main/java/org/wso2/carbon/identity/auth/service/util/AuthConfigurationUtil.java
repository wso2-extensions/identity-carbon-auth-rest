package org.wso2.carbon.identity.auth.service.util;

import org.apache.axiom.om.OMElement;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.auth.service.internal.AuthenticationServiceHolder;
import org.wso2.carbon.identity.auth.service.module.ResourceConfig;
import org.wso2.carbon.identity.auth.service.module.ResourceConfigKey;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.securevault.SecretResolver;
import org.wso2.securevault.SecretResolverFactory;
import org.wso2.securevault.commons.MiscellaneousUtil;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.xml.namespace.QName;

public class AuthConfigurationUtil {

    private static AuthConfigurationUtil authConfigurationUtil = new AuthConfigurationUtil();

    private Map<ResourceConfigKey, ResourceConfig> resourceConfigMap = new LinkedHashMap<>();
    private Map<String, String> applicationConfigMap = new HashMap<>();
    private List<String> intermediateCertCNList = new ArrayList<>();
    private List<String> exemptedContextList = new ArrayList<>();
    private boolean isIntermediateCertValidationEnabled = false;
    private static final String SECRET_ALIAS = "secretAlias";
    private static final String SECRET_ALIAS_NAMESPACE_URI = "http://org.wso2.securevault/configuration";
    private static final String SECRET_ALIAS_PREFIX = "svns";
    private String defaultAccess;
    private boolean isScopeValidationEnabled = true;

    private static final Log log = LogFactory.getLog(AuthConfigurationUtil.class);

    private AuthConfigurationUtil() {
    }

    public static AuthConfigurationUtil getInstance() {
        return AuthConfigurationUtil.authConfigurationUtil;
    }

    public ResourceConfig getSecuredConfig(ResourceConfigKey resourceConfigKey) {
        ResourceConfig resourceConfig = null;
        for ( Map.Entry<ResourceConfigKey, ResourceConfig> entry : resourceConfigMap.entrySet() ) {
            if ( entry.getKey().equals(resourceConfigKey) ) {
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

        OMElement resourceAccessControl = IdentityConfigParser.getInstance().getConfigElement(Constants
                .RESOURCE_ACCESS_CONTROL_ELE);
        if ( resourceAccessControl != null ) {
            defaultAccess = resourceAccessControl.getAttributeValue(new QName(Constants.RESOURCE_DEFAULT_ACCESS));
            isScopeValidationEnabled = !Boolean.parseBoolean(resourceAccessControl
                    .getAttributeValue(new QName(Constants.RESOURCE_DISABLE_SCOPE_VALIDATION)));
            Iterator<OMElement> resources = resourceAccessControl.getChildrenWithName(
                    new QName(IdentityCoreConstants.IDENTITY_DEFAULT_NAMESPACE, Constants.RESOURCE_ELE));
            if ( resources != null ) {

                while ( resources.hasNext() ) {
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
                    ResourceConfigKey resourceConfigKey = new ResourceConfigKey(context, httpMethod);
                    if (!resourceConfigMap.containsKey(resourceConfigKey)) {
                        resourceConfigMap.put(resourceConfigKey, resourceConfig);
                    }
                }
            }
        }
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
            String regex = "\\s*,\\s*";
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

    public boolean isIntermediateCertValidationEnabled() {

        return isIntermediateCertValidationEnabled;
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
     */
    public static boolean isAuthHeaderMatch(MessageContext messageContext, String authHeaderIdentifier) {

        if (messageContext instanceof AuthenticationContext) {
            AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;
            if (authenticationContext.getAuthenticationRequest() != null) {
                String authorizationHeader = authenticationContext.getAuthenticationRequest().
                        getHeader(HttpHeaders.AUTHORIZATION);
                if (StringUtils.isBlank(authorizationHeader)) {
                    return false;
                }
                String[] splitAuthorizationHeader = authorizationHeader.split(" ");
                return splitAuthorizationHeader.length > 0 &&
                        StringUtils.isNotEmpty(splitAuthorizationHeader[0]) &&
                        authHeaderIdentifier.equals(splitAuthorizationHeader[0]);
            }
        }
        return false;
    }
}
