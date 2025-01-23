package org.wso2.carbon.identity.auth.service.util;


public class Constants {

    public final static String RESOURCE_ACCESS_CONTROL_ELE = "ResourceAccessControl";
    public final static String RESOURCE_ELE = "Resource";
    public final static String RESOURCE_DEFAULT_ACCESS = "default-access";
    public final static String RESOURCE_DISABLE_SCOPE_VALIDATION = "disable-scope-validation";
    public final static String RESOURCE_CONTEXT_ATTR = "context";
    public final static String RESOURCE_SECURED_ATTR = "secured";
    public final static String RESOURCE_HTTP_METHOD_ATTR = "http-method";
    public final static String RESOURCE_ACCESS_CONTROL = "access-control";
    public final static String RESOURCE_PERMISSION_ELE = "Permissions";
    public final static String RESOURCE_SCOPE_ELE = "Scopes";
    public final static String OAUTH2_ALLOWED_SCOPES = "oauth2-allowed-scopes";
    public final static String OAUTH2_VALIDATE_SCOPE = "oauth2-validate-scopes";
    public final static String RESOURCE_CROSS_TENANT_ATTR = "cross-tenant";
    public final static String RESOURCE_CROSS_ACCESS_ALLOWED_TENANTS = "cross-access-allowed-tenants";
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
    private final static String ACCESS_CONTROL_STATUS_DENY = "deny";

    public final static String COOKIE_BASED_TOKEN_BINDING = "cookie";
    public final static String COOKIE_BASED_TOKEN_BINDING_EXT_PARAM = "atbv";

    public final static String CURRENT_SESSION_IDENTIFIER = "currentSessionIdentifier";

    public final static String BASIC_CLIENT_AUTH_HANDLER = "BasicClientAuthentication";

    public final static String AUTH_CONTEXT_OAUTH_APP_PROPERTY = "oAuthAppDO";

    public static final String AUTHENTICATED_WITH_BASIC_AUTH = "AuthenticatedWithBasicAuth";
    public static final String IS_FEDERATED_USER = "isFederatedUser";
    public static final String IDP_NAME = "idpName";

    public final static String AUTHORIZATION_CONTROL_ELE = "AuthorizationControl";
    public final static String SKIP_AUTHORIZATION_ELE = "SkipAuthorization";
    public final static String AUTH_HANDLER_ELE = "authHandler";
    public final static String ENDPOINT_LIST_ELE = "endpoints";
    public static final String ENGAGED_AUTH_HANDLER = "engagedAuthHandler";
    public static final String BASIC_AUTHENTICATION = "BasicAuthentication";
    public static final String ENABLE_BASIC_AUTH_HANDLER_CONFIG = "EnableBasicAuthHandler";
    public static final String RESOURCE_ACCESS_CONTROL_V2_FILE = "resource-access-control-v2.xml";
    public static final String AUTHENTICATION_TYPE = "authenticationType";
    public final static String VALIDATE_LEGACY_PERMISSIONS = "validateLegacyPermissions";

    // Audit Log Constants.
    public static final String INITIATOR = "Initiator";
    public static final String ACTION = "Action";
    public static final String TARGET = "Target";
    public static final String DATA = "Data";
    public static final String OUTCOME = "Outcome";

    // Impersonation Constants.
    public static final String ACT = "act";
    public static final String SUB = "sub";
    public static final String GET = "GET";
    public static final String POST = "POST";
    public static final String PATCH = "PATCH";
    public static final String DELETE = "DELETE";
    public static final String AUTHORIZED = "AUTHORIZED";
    public static final String IMPERSONATION_RESOURCE_MODIFICATION = "resource-modification-via-impersonation";
    public static final String IMPERSONATION_RESOURCE_ACCESS = "resource-access-via-impersonation";
    public static final String IMPERSONATION_RESOURCE_DELETION = "resource-deletion-via-impersonation";
    public static final String IMPERSONATION_RESOURCE_CREATION = "resource-creation-via-impersonation";
    public static final String SUBJECT = "subject";
    public static final String IMPERSONATOR = "impersonator";
    public static final String RESOURCE_PATH = "ResourcePath";
    public static final String HTTP_METHOD = "httpMethod";
    public static final String CLIENT_ID = "clientId";
    public static final String SCOPE = "scope";
}
