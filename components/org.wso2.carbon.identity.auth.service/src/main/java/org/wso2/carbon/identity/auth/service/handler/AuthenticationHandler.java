/*
 * Copyright (c) 2016-2023, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.auth.service.handler;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.auth.service.exception.AuthClientException;
import org.wso2.carbon.identity.auth.service.exception.AuthServerException;
import org.wso2.carbon.identity.auth.service.exception.AuthenticationFailException;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.AbstractIdentityMessageHandler;
import org.wso2.carbon.identity.core.util.IdentityUtil;

/**
 * This is the abstract class for custom authentication handlers.
 *
 * The custom handlers should implement the doAuthenticate() method and optionally the postAuthenticate() method.
 */
public abstract class AuthenticationHandler extends AbstractIdentityMessageHandler {

    private static final Log LOG = LogFactory.getLog(AuthenticationHandler.class);

    public int getPriority(MessageContext messageContext, int defaultValue) {

        int priority = super.getPriority(messageContext);
        return priority != -1 ? priority : defaultValue;
    }

    /**
     *
     * This method is called by the authentication framework.
     *
     * @param messageContext
     * @return
     * @throws AuthServerException
     * @throws AuthenticationFailException
     * @throws AuthClientException
     */
    public final AuthenticationResult authenticate(MessageContext messageContext) throws AuthServerException, AuthenticationFailException, AuthClientException {

        AuthenticationResult authenticationResult = this.doAuthenticate(messageContext);
        postAuthenticate(messageContext, authenticationResult);

        return authenticationResult;

    }

    /**
     *
     * This is where the actual authentication takes place.
     *
     * @param messageContext
     * @return
     * @throws AuthServerException
     * @throws AuthenticationFailException
     * @throws AuthClientException
     */
    protected abstract AuthenticationResult doAuthenticate(MessageContext messageContext) throws AuthServerException, AuthenticationFailException, AuthClientException;

    /**
     *
     * This is the post authenticate hook.
     *
     * A custom authentication handler can provide its own implementation for the hook.
     *
     * The default behaviour is to set the user details in {@link org.wso2.carbon.context.CarbonContext}
     *
     * @param messageContext
     */
    protected void postAuthenticate(MessageContext messageContext, AuthenticationResult authenticationResult) {

        AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;

        if (AuthenticationStatus.SUCCESS.equals(authenticationResult.getAuthenticationStatus())) {

            User user = authenticationContext.getUser();
            if (user != null) {
                // Set the user in to the Carbon context if the user belongs to same tenant or else if the accessing
                // organization is authorized to access. Skip this for cross tenant scenarios.

                String authorizedOrganization = null;
                String userResidentOrganization = null;
                if (user instanceof AuthenticatedUser) {
                    authorizedOrganization = ((AuthenticatedUser) user).getAccessingOrganization();
                    userResidentOrganization = ((AuthenticatedUser) user).getUserResidentOrganization();
                }

                if (user.getTenantDomain() != null && (user.getTenantDomain()
                        .equalsIgnoreCase(PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain()) ||
                        StringUtils.isNotEmpty(authorizedOrganization))) {
                    PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(IdentityUtil.addDomainToName
                            (user.getUserName(), user.getUserStoreDomain()));
                    // Set the user's resident organization if user is accessing an organization
                    PrivilegedCarbonContext.getThreadLocalCarbonContext()
                            .setUserResidentOrganizationId(userResidentOrganization);
                }
                // Set the user id to the Carbon context if the user authentication is succeeded.
                try {
                    AuthenticatedUser authenticatedUser;
                    if (user instanceof AuthenticatedUser) {
                        authenticatedUser = (AuthenticatedUser) user;
                        // For B2B organization users, set the user ID which is set as username in user object.
                        if (authenticatedUser.isFederatedUser() && StringUtils.isNotEmpty(authorizedOrganization)) {
                            PrivilegedCarbonContext.getThreadLocalCarbonContext()
                                    .setUserId(authenticatedUser.getUserName());
                            return;
                        }
                    } else {
                        authenticatedUser = new AuthenticatedUser(user);
                    }
                    PrivilegedCarbonContext.getThreadLocalCarbonContext().setUserId(authenticatedUser.getUserId());
                } catch (UserIdNotFoundException e) {
                    LOG.error("User id not found for user: " + user.getLoggableMaskedUserId());
                }
            }
        }
    }
}
