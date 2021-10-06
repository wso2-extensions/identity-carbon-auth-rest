package org.wso2.carbon.identity.auth.service.util;


public class Constants {

    public final static String RESOURCE_ACCESS_CONTROL_ELE = "ResourceAccessControl";
    public final static String RESOURCE_ELE = "Resource";
    public final static String RESOURCE_DEFAULT_ACCESS = "default-access";
    public final static String RESOURCE_DISABLE_SCOPE_VALIDATION = "disable-scope-validation";
    public final static String RESOURCE_CONTEXT_ATTR = "context";
    public final static String RESOURCE_SECURED_ATTR = "secured";
    public final static String RESOURCE_HTTP_METHOD_ATTR = "http-method";
    public final static String RESOURCE_PERMISSION_ELE = "Permissions";
    public final static String RESOURCE_SCOPE_ELE = "Scopes";
    public final static String OAUTH2_ALLOWED_SCOPES = "oauth2-allowed-scopes";
    public final static String OAUTH2_VALIDATE_SCOPE = "oauth2-validate-scopes";
    public final static String RESOURCE_CROSS_TENANT_ATTR = "cross-tenant";
    public final static String RESOURCE_ALLOWED_TENANTS = "allowed-tenants";
    public final static String RESOURCE_ALLOWED_AUTH_HANDLERS = "allowed-auth-handlers";
    public final static String RESOURCE_ALLOWED_AUTH_HANDLERS_ALL = "all";

    public final static String CLIENT_APP_AUTHENTICATION_ELE = "ClientAppAuthentication";
    public final static String APPLICATION_NAME_ATTR = "name";
    public final static String APPLICATION_HASH_ATTR = "hash";
    public final static String APPLICATION_ELE = "Application";
    public static final String JSESSIONID = "JSESSIONID";
    public static final String COOKIE_AUTH_HEADER = "Cookie";

    public static final String INTERMEDIATE_CERT_VALIDATION_ELE = "IntermediateCertValidation";
    public static final String INTERMEDIATE_CERTS_ELE = "IntermediateCerts";
    public static final String EXEMPT_CONTEXT_ELE = "ExemptContext";
    public static final String CERT_CN_ELE = "CertCN";
    public final static String CONTEXT_ELE = "Context";
    public final static String CERT_AUTHENTICATION_ENABLE_ATTR = "enable";
    public final static String DENY_DEFAULT_ACCESS = "deny";

    public final static String COOKIE_BASED_TOKEN_BINDING = "cookie";
    public final static String COOKIE_BASED_TOKEN_BINDING_EXT_PARAM = "atbv";

    public final static String CURRENT_SESSION_IDENTIFIER = "currentSessionIdentifier";

    public final static String BASIC_CLIENT_AUTH_HANDLER = "BasicClientAuthentication";

    public final static String AUTH_CONTEXT_OAUTH_APP_PROPERTY = "oAuthAppDO";

    public static final String AUTHENTICATED_WITH_BASIC_AUTH = "AuthenticatedWithBasicAuth";
}
