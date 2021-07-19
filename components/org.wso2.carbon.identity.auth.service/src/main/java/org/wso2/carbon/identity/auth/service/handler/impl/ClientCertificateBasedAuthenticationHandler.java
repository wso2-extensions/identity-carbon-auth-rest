/*
 *
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   you may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */

package org.wso2.carbon.identity.auth.service.handler.impl;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.auth.service.exception.AuthClientException;
import org.wso2.carbon.identity.auth.service.exception.AuthServerException;
import org.wso2.carbon.identity.auth.service.exception.AuthenticationFailException;
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.auth.service.util.AuthConfigurationUtil;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.security.cert.X509Certificate;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

/**
 * This authentication handler does the the authentication based on client certificate.
 * The client's' SSL certificate should be verified by the HTTP container.
 * This handler checked whether the certificate is verified by the container.
 * If yes, the value of the 'User' HTTP header will be treated as the authenticated user.
 */
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
                return true;
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

                if (requireIntermediateCertValidation(authenticationContext)) {
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
                }
                if (StringUtils.isNotEmpty(username)) {
                    String tenantDomain = MultitenantUtils.getTenantDomain(username);

                    // Get rid of the tenant domain name suffix, if the user belongs to the super tenant.
                    if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {

                        String superTenantSuffix = "@" + MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

                        if (username.endsWith(superTenantSuffix)) {
                            username = username.substring(0, username.length() - superTenantSuffix.length());
                        }
                    }
                    String userStoreDomain = UserCoreUtil.extractDomainFromName(username);
                    username = UserCoreUtil.removeDomainFromName(username);

                    User user = new User();
                    user.setUserName(username);
                    user.setTenantDomain(tenantDomain);
                    user.setUserStoreDomain(userStoreDomain);

                    authenticationContext.setUser(user);

                    authenticationResult.setAuthenticationStatus(AuthenticationStatus.SUCCESS);

                    if (log.isDebugEnabled()) {
                        log.debug(String.format("Client certificate based authentication was successful. " +
                                "Set '%s' as the user", username));
                    }
                } else {
                    //Server to server authentication. No user involves
                    authenticationResult.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
                }

            }
        }

        return authenticationResult;
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

}
