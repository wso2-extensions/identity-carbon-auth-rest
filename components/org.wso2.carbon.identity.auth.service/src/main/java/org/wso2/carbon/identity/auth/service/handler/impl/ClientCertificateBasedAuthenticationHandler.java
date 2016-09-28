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
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.auth.service.exception.AuthClientException;
import org.wso2.carbon.identity.auth.service.exception.AuthServerException;
import org.wso2.carbon.identity.auth.service.exception.AuthenticationFailException;
import org.wso2.carbon.identity.auth.service.handler.AuthenticationHandler;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.InitConfig;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

/**
 * This authentication handler does the the authentication based on client certificate.
 * The client's' SSL certificate should be verified by the HTTP container.
 * This handler checked whether the certificate is verified by the container.
 * If yes, the value of the 'User' HTTP header will be treated as the authenticated user.
 */
public class ClientCertificateBasedAuthenticationHandler implements AuthenticationHandler {

    private static final Log log = LogFactory.getLog(ClientCertificateBasedAuthenticationHandler.class);
    private static final String CLIENT_CERTIFICATE_ATTRIBUTE_NAME = "javax.servlet.request.X509Certificate";

    @Override
    public void init(InitConfig initConfig) {

    }

    @Override
    public String getName() {
        return "ClientCertificate";
    }

    @Override
    public boolean isEnabled(MessageContext messageContext) {
        return true;
    }

    @Override
    public int getPriority(MessageContext messageContext) {
        return 100;
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
    public AuthenticationResult authenticate(MessageContext messageContext)
            throws AuthServerException, AuthenticationFailException, AuthClientException {

        AuthenticationResult authenticationResult = new AuthenticationResult(AuthenticationStatus.FAILED);

        if (messageContext instanceof AuthenticationContext) {
            AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;
            if (authenticationContext.getAuthenticationRequest() != null &&
                    authenticationContext.getAuthenticationRequest().
                            getAttribute(CLIENT_CERTIFICATE_ATTRIBUTE_NAME) != null
                    ) {

                String username = authenticationContext.getAuthenticationRequest().getHeader("WSO2-Identity-User");

                if (StringUtils.isNotEmpty(username)) {
                    String tenantDomain = MultitenantUtils.getTenantDomain(username);

                    User user = new User();
                    user.setUserName(MultitenantUtils.getTenantAwareUsername(username));
                    user.setTenantDomain(tenantDomain);

                    authenticationContext.setUser(user);

                    authenticationResult.setAuthenticationStatus(AuthenticationStatus.SUCCESS);

                    if (log.isDebugEnabled()) {
                        log.debug(String.format("Client certificate based authentication was successful. " +
                                "Set '%s' as the user", username));
                    }

                    // Set Carbon context values.
                    PrivilegedCarbonContext.getThreadLocalCarbonContext().
                            setUsername(MultitenantUtils.getTenantAwareUsername(username));
                    PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain);

                    int tenantId = IdentityTenantUtil.getTenantIdOfUser(username);
                    PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(tenantId);
                }

            }
        }

        return authenticationResult;
    }

}
