/*
 * Copyright (c) 2016-2025, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.carbon.identity.auth.service.handler.impl;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.annotation.bundle.Capability;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.auth.service.exception.AuthClientException;
import org.wso2.carbon.identity.auth.service.exception.AuthServerException;
import org.wso2.carbon.identity.auth.service.exception.AuthenticationFailException;
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.auth.service.internal.AuthenticationServiceHolder;
import org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil;
import org.wso2.carbon.identity.auth.service.util.Constants;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.context.IdentityContext;
import org.wso2.carbon.identity.core.context.model.ApplicationActor;
import org.wso2.carbon.identity.core.context.model.UserActor;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

/**
 * This authentication handler does the the authentication based on client certificate.
 * The client's' SSL certificate should be verified by the HTTP container.
 * This handler checked whether the certificate is verified by the container.
 * If yes, the value of the 'User' HTTP header will be treated as the authenticated user.
 */
@Capability(
        namespace = "osgi.service",
        attribute = {
                "objectClass=org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler",
                "service.scope=singleton"
        }
)
public class ClientCertificateBasedAuthenticationHandler extends AuthenticationHandler {

    private static final Log log = LogFactory.getLog(ClientCertificateBasedAuthenticationHandler.class);
    private static final String CLIENT_CERTIFICATE_ATTRIBUTE_NAME = "javax.servlet.request.X509Certificate";
    private static final String USER_HEADER_NAME = "WSO2-Identity-User";
    private static final String CERTIFICATE_ATTRIBUTE_CN = "CN";

    @Override
    public void init(InitConfig initConfig) {

    }

    @Override
    public String getName() {
        return "ClientCertificate";
    }

    @Override
    public int getPriority(MessageContext messageContext) {
        return getPriority(messageContext, 10);
    }

    @Override
    public boolean canHandle(MessageContext messageContext) {

        if (messageContext instanceof AuthenticationContext) {
            AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;
            if (authenticationContext.getAuthenticationRequest() != null &&
                    authenticationContext.getAuthenticationRequest().
                            getAttribute(CLIENT_CERTIFICATE_ATTRIBUTE_NAME) != null) {
                if (requireIntermediateCertValidation(authenticationContext)) {
                    log.debug("Intermediate certificate validation is enabled.");
                    return true;
                }
                if (AuthConfigurationUtil.getInstance().IsClientCertBasedAuthnEnabled()) {
                    log.debug("Client certificate based authentication is enabled.");
                    return true;
                }
                return false;
            }
        }
        return false;
    }

    @Override
    protected AuthenticationResult doAuthenticate(MessageContext messageContext)
            throws AuthServerException, AuthenticationFailException, AuthClientException {

        AuthenticationResult authenticationResult = new AuthenticationResult(AuthenticationStatus.FAILED);

        if (messageContext instanceof AuthenticationContext) {
            AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;
            if (authenticationContext.getAuthenticationRequest() != null &&
                    authenticationContext.getAuthenticationRequest().
                            getAttribute(CLIENT_CERTIFICATE_ATTRIBUTE_NAME) != null
                    ) {

                String username = authenticationContext.getAuthenticationRequest().getHeader(USER_HEADER_NAME);
                Object object = authenticationContext.getAuthenticationRequest()
                        .getAttribute(CLIENT_CERTIFICATE_ATTRIBUTE_NAME);
                if (!(object instanceof X509Certificate[])) {
                    throw new AuthenticationFailException("Exception while casting the X509Certificate.");
                }
                X509Certificate[] certificates = (X509Certificate[]) object;
                if (certificates.length == 0) {
                    throw new AuthenticationFailException("X509Certificate object is null.");
                }
                X509Certificate cert = certificates[0];

                if (requireIntermediateCertValidation(authenticationContext)) {
                    try {
                        username = getCN(cert.getSubjectDN().getName());
                    } catch (InvalidNameException e) {
                        throw new AuthenticationFailException("Error occurred when retrieving cert CN.", e);
                    }
                    if (StringUtils.isBlank(username)) {
                        log.error("Authentication failed. Username retrieved from the certificate CN is empty.");
                        return authenticationResult;
                    }
                    String certIssuerCN;
                    try {
                        certIssuerCN = getCN(cert.getIssuerDN().getName());
                    } catch (InvalidNameException e) {
                        throw new AuthenticationFailException("Error occurred when retrieving cert issuer CN.", e);
                    }
                    if (StringUtils.isEmpty(certIssuerCN) || !AuthConfigurationUtil.getInstance()
                            .getIntermediateCertCNList().contains(certIssuerCN)) {
                        log.error("Authentication failed for certificate issuer: " + certIssuerCN +
                                " called by user: "+ username + ".");
                        return authenticationResult;
                    }
                } else {
                    final String certIssuer;
                    final String thumbprint;
                    try {
                        certIssuer = cert.getIssuerDN().getName();
                        if (StringUtils.isEmpty(certIssuer)) {
                            log.debug("Authentication failed. Issuer of the certificate is empty.");
                            return authenticationResult;
                        }
                        thumbprint = getSha256Fingerprint(cert);
                    } catch (CertificateEncodingException | NoSuchAlgorithmException e) {
                        throw new AuthenticationFailException("Error occurred while retrieving certificate " +
                                "thumbprint.", e);
                    }
                    if (StringUtils.isNotEmpty(username)) {
                        //  USER-BASED AUTH
                        List<AuthConfigurationUtil.CertUserMapping> certUserMapping =
                                AuthConfigurationUtil.getInstance().getCertUserMappings();

                        if (CollectionUtils.isEmpty(certUserMapping)) {
                            // At least one mapping with trusted issuer should exist.
                            log.debug("User based authentication failed. User and cert mapping is not configured.");
                            return authenticationResult;
                        }

                        if (!doesIssuerExistsInAllowedListForUserBasedAuthn(certUserMapping, certIssuer)) {
                            log.debug("User based authentication failed. Issuer of the certificate " +
                                    "does not exist in the trusted issuer list.");
                            return authenticationResult;
                        }

                        // 1) Exact mapping for this thumbprint → pick the FIRST
                        Optional<AuthConfigurationUtil.CertUserMapping> exactMatch =
                                certUserMapping.stream()
                                        .filter(m -> isDNEqual(certIssuer, m.getAllowedIssuer()) &&
                                                thumbprint.equalsIgnoreCase(m.getAllowedThumbprint()))
                                        .findFirst();

                        if (exactMatch.isPresent()) {
                            List<String> allowedUsers = exactMatch.get().getAllowedUsernames();
                            if (allowedUsers.contains(Constants.WILDCARD)) {
                                log.debug("Wildcard user found. Allowing the user to proceed with " +
                                        "User based authentication.");
                            } else if (!checkUserExistenceInAllowedList(allowedUsers, username)) {
                                log.debug("Authentication failed. Username from the header is not in the " +
                                        "allowed user list.");
                                return authenticationResult;
                            }
                        } else {

                            //  No exact thumbprint mapping, trying wildcard mapping ("*")
                            Optional<AuthConfigurationUtil.CertUserMapping> wildcardMap =
                                    certUserMapping.stream()
                                            .filter(m -> isDNEqual(certIssuer, m.getAllowedIssuer())
                                                    && Constants.WILDCARD.equals(m.getAllowedThumbprint()))
                                            .findFirst();

                            if (wildcardMap.isPresent()) {
                                List<String> allowedUsers = wildcardMap.get().getAllowedUsernames();
                                if (allowedUsers.contains(Constants.WILDCARD)) {
                                    log.debug("Wildcard user found. Allowing the user to proceed with " +
                                            "User based authentication.");
                                } else if (!checkUserExistenceInAllowedList(allowedUsers, username)) {
                                    log.debug("Authentication failed. Username from the header is not in the " +
                                            "allowed user list.");
                                    return authenticationResult;
                                }
                            } else {
                                log.debug("Authentication failed. No thumbprint mapping found for the issuer.");
                                return authenticationResult;
                            }
                        }
                    } else {
                        //  M2M / SYSTEM AUTH
                        List<AuthConfigurationUtil.SystemThumbprintMapping> systemUserThumbprintMappings =
                                AuthConfigurationUtil.getInstance().getSystemUserThumbprintMappings();

                        if (CollectionUtils.isEmpty(systemUserThumbprintMappings)) {
                            // At least one mapping with trusted issuer should exists
                            log.debug("Authentication failed. System user and thumbprint mapping is not " +
                                    "configured.");
                            return authenticationResult;
                        }

                        if (!doesIssuerExistsInAllowedList(systemUserThumbprintMappings, certIssuer)) {
                            log.debug("Authentication failed. Issuer of the certificate does not exist" +
                                    " in the trusted issuer list.");
                            return authenticationResult;
                        }

                        // 1) Exact mapping for this thumbprint → pick the FIRST
                        Optional<AuthConfigurationUtil.SystemThumbprintMapping> exactMatch =
                                systemUserThumbprintMappings.stream()
                                        .filter(m ->
                                                isDNEqual(certIssuer, m.getAllowedIssuer())
                                                        && thumbprint.equalsIgnoreCase(m.getAllowedThumbprint()))
                                        .findFirst();

                        if (exactMatch.isPresent()) {
                            String allowedUser = exactMatch.get().getAllowedSystemUser();
                            if (Constants.WILDCARD.equals(allowedUser)) {
                                // When the wildcard is set as the system user, we do not set any user in the context.
                                authenticationResult.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
                                return authenticationResult;
                            }
                            username = allowedUser;
                        } else {
                            // No exact system thumbprint mapping. Trying wildcard thumbprint mapping ("*")
                            Optional<AuthConfigurationUtil.SystemThumbprintMapping> wildcardMap =
                                    systemUserThumbprintMappings.stream()
                                            .filter(m ->
                                                    isDNEqual(certIssuer, m.getAllowedIssuer())
                                                            && Constants.WILDCARD.equals(m.getAllowedThumbprint()))
                                            .findFirst();

                            if (wildcardMap.isPresent()) {
                                String allowedUser = wildcardMap.get().getAllowedSystemUser();
                                if (Constants.WILDCARD.equals(allowedUser)) {
                                    // To preserve the backward compatibility.
                                    authenticationResult.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
                                    return authenticationResult;
                                }
                                username = allowedUser;
                            } else {
                                log.debug("Authentication failed. No thumbprint mapping found for the issuer.");
                                return authenticationResult;
                            }
                        }
                    }
                }

                if (StringUtils.isNotEmpty(username)) {
                    try {
                        // username is expected to be fully qualified. Eg: <UserStoreDomain>/<Username>@<TenantDomain>
                        String tenantDomain = MultitenantUtils.getTenantDomain(username);
                        int tenantId = IdentityTenantUtil.getTenantIdOfUser(username);

                        // Get rid of the tenant domain name suffix, if the user belongs to the super tenant.
                        if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {

                            String superTenantSuffix = "@" + MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

                            if (username.endsWith(superTenantSuffix)) {
                                username = username.substring(0, username.length() - superTenantSuffix.length());
                            }
                        } else {
                            int lastAtIndex = username.lastIndexOf('@');
                            if (lastAtIndex != -1) {
                                username = username.substring(0, lastAtIndex);
                            }
                        }
                        String userStoreDomain = UserCoreUtil.extractDomainFromName(username);
                        username = UserCoreUtil.removeDomainFromName(username);

                        // Check if user exists in the user store.
                        AbstractUserStoreManager userStoreManager;
                        UserRealm userRealm = AuthenticationServiceHolder.getInstance().getRealmService().
                                getTenantUserRealm(tenantId);
                        if (userRealm != null) {
                            userStoreManager = (AbstractUserStoreManager) userRealm.getUserStoreManager();
                            boolean userExists = userStoreManager.isExistingUser(username);

                            if (!userExists) {
                                if (log.isDebugEnabled()) {
                                    log.debug("Authentication failed. User: " + username + " does not exist.");
                                }
                                return authenticationResult;
                            }
                        }

                        AuthenticatedUser user = new AuthenticatedUser();
                        user.setUserName(MultitenantUtils.getTenantAwareUsername(username));
                        user.setTenantDomain(tenantDomain);
                        user.setUserStoreDomain(userStoreDomain);

                        authenticationContext.setUser(user);

                        authenticationResult.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
                        addActorToIdentityContext(user);

                        if (log.isDebugEnabled()) {
                            log.debug(String.format("Client certificate based authentication was successful. " +
                                    "Set '%s' as the user", username));
                        }
                    } catch (Exception e) {
                        throw new AuthenticationFailException("Error occurred while validating the user");
                    }
                } else {
                    //Server to server authentication. No user involves
                    authenticationResult.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
                }
            }
        }

        return authenticationResult;
    }

    private boolean doesIssuerExistsInAllowedList(
            List<AuthConfigurationUtil.SystemThumbprintMapping> systemUserThumbprintMappings, String certIssuer) {

        Optional<AuthConfigurationUtil.SystemThumbprintMapping> issuerExists =
                systemUserThumbprintMappings.stream()
                        .filter(m -> isDNEqual(certIssuer, m.getAllowedIssuer()))
                        .findFirst();

        return issuerExists.isPresent();
    }

    private boolean doesIssuerExistsInAllowedListForUserBasedAuthn(
            List<AuthConfigurationUtil.CertUserMapping> certUserMapping, String certIssuer) {


        Optional<AuthConfigurationUtil.CertUserMapping> issuerExists =
                certUserMapping.stream()
                        .filter(m -> isDNEqual(certIssuer,m.getAllowedIssuer()))
                        .findFirst();

        return issuerExists.isPresent();
    }

    /**
     * Checks whether intermediate certificate validation is required for the incoming request.
     *
     * @param authenticationContext authenticationContext.
     * @return True if intermediate certificate validation is required.
     */
    private boolean requireIntermediateCertValidation(AuthenticationContext authenticationContext) {

        if (!AuthConfigurationUtil.getInstance().isIntermediateCertValidationEnabled()) {
            return false;
        }
        for (String context : AuthConfigurationUtil.getInstance().getExemptedContextList()) {
            if (authenticationContext.getAuthenticationRequest().getContextPath().contains(context)) {
                return false;
            }
        }
        return true;
    }

    // Check whether the user exists in the allowed user list.
    private boolean checkUserExistenceInAllowedList(List<String> values, String probe) {

        if (values == null || StringUtils.isEmpty(probe)) return false;
        for (String v : values) {
            if (StringUtils.equalsIgnoreCase(v, probe)) return true;
        }
        return false;
    }


    /**
     * Retrieve the common name from the subject DN.
     *
     * @param dn Subject DN.
     * @return Common name.
     * @throws InvalidNameException
     */
    private String getCN(String dn) throws InvalidNameException {

        LdapName ln = new LdapName(dn);
        for (Rdn rdn : ln.getRdns()) {
            if (rdn.getType().equalsIgnoreCase(CERTIFICATE_ATTRIBUTE_CN)) {
                return String.valueOf(rdn.getValue());
            }
        }
        return StringUtils.EMPTY;
    }

    private void addActorToIdentityContext(User user) {

        UserActor userActor = new UserActor.Builder()
                .username(user.getUserName())
                .build();
        IdentityContext.getThreadLocalIdentityContext().setActor(userActor);
    }

    // Generate SHA-256 fingerprint of the certificate.
    private String getSha256Fingerprint(X509Certificate cert)
            throws CertificateEncodingException, NoSuchAlgorithmException {

        byte[] encoded = cert.getEncoded();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(encoded);

        StringBuilder fingerprint = new StringBuilder();
        for (byte b : digest) {
            fingerprint.append(String.format("%02X:", b));
        }

        // Remove trailing colon
        if (fingerprint.length() > 0) {
            fingerprint.setLength(fingerprint.length() - 1);
        }

        return fingerprint.toString();
    }

    // Check if the two DNs are equal after normalizing them.
    private boolean isDNEqual(String certDN, String trustedDN) {

        if (StringUtils.isEmpty(trustedDN) || StringUtils.isEmpty(certDN)) {
            return false;
        }

        if (certDN.equals(trustedDN)) {
            return true;
        }

        // Normalize and compare DN components.
        String normalizedDN1 = normalizeDN(certDN);
        String normalizedDN2 = normalizeDN(trustedDN);
        return normalizedDN1.equals(normalizedDN2);
    }

    /**
     * Helper method to normalize a Distinguished Name by sorting its components.
     * This ensures that DNs with the same components in different orders are normalized to the same string.
     *
     * @param dn Distinguished Name to normalize
     * @return Normalized DN string with components sorted alphabetically
     */
    private static String normalizeDN(String dn) {

        if (dn == null || dn.trim().isEmpty()) {
            return dn;
        }

        try {
            // Split DN into components and normalize each.
            String[] components = dn.split(",");
            String[] normalizedComponents = new String[components.length];

            for (int i = 0; i < components.length; i++) {
                String component = components[i].trim();
                // Normalize whitespace around the equals sign.
                if (component.contains("=")) {
                    String[] parts = component.split("=", 2);
                    if (parts.length == 2) {
                        normalizedComponents[i] = parts[0].trim().toUpperCase() + "=" + parts[1].trim();
                    } else {
                        normalizedComponents[i] = component;
                    }
                } else {
                    normalizedComponents[i] = component;
                }
            }

            // Sort components to ensure consistent ordering.
            java.util.Arrays.sort(normalizedComponents);

            StringBuilder normalized = new StringBuilder();
            for (int i = 0; i < normalizedComponents.length; i++) {
                if (i > 0) {
                    normalized.append(", ");
                }
                normalized.append(normalizedComponents[i]);
            }

            String result = normalized.toString();

            if (log.isDebugEnabled()) {
                if (!dn.equals(result)) {
                    log.debug("Normalized DN from '" + dn + "' to '" + result + "'");
                }
            }

            return result;
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to normalize DN: " + dn + ". Using original DN. Error: " + e.getMessage());
            }
            return dn; // Return original DN if normalization fails.
        }
    }
}
