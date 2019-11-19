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

package org.wso2.carbon.identity.auth.service.handler;

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
import org.wso2.carbon.identity.auth.service.internal.AuthenticationServiceHolder;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.AbstractIdentityMessageHandler;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.user.account.association.UserAccountConnector;
import org.wso2.carbon.identity.user.account.association.dto.UserAccountAssociationDTO;
import org.wso2.carbon.identity.user.account.association.exception.UserAccountAssociationException;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import static org.wso2.carbon.utils.multitenancy.MultitenantUtils.getTenantDomain;

/**
 * This is the abstract class for custom authentication handlers.
 *
 * The custom handlers should implement the doAuthenticate() method and optionally the postAuthenticate() method.
 *
 */
public abstract class AuthenticationHandler extends AbstractIdentityMessageHandler {

    private static final Log log = LogFactory.getLog(AuthenticationHandler.class);
    private static final String ASSOCIATED_USER_ID_HEADER = "AssociatedUserId";

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
                // Set the user in to the Carbon context if the user belongs to same tenant. Skip this for cross tenant
                // scenarios.

                if (user.getTenantDomain() != null && user.getTenantDomain().equalsIgnoreCase(PrivilegedCarbonContext
                        .getThreadLocalCarbonContext().getTenantDomain())) {

                    String associatedUserRequestHeader = authenticationContext.getAuthenticationRequest().
                            getHeader(ASSOCIATED_USER_ID_HEADER);
                    if (StringUtils.isNotEmpty(associatedUserRequestHeader)) {
                        User associatedUser = getAssociatedUser(user, associatedUserRequestHeader);
                        if (associatedUser == null) {
                            log.error("Cannot get the associated user for the provided header value: "
                                    + associatedUserRequestHeader);
                            setFailedAuthentication(authenticationResult);
                            return;
                        }
                        if (!user.equals(associatedUser)) {
                            setAssociatedUserInCarbonContext(user, associatedUser, authenticationResult);
                            return;
                        }
                    }
                    String domainAwareUserName = IdentityUtil.addDomainToName(user.getUserName(),
                            user.getUserStoreDomain());
                    setUserInCarbonContext(domainAwareUserName);
                }
            }
        }
    }

    private User getAssociatedUser(User user, String associatedUserRequestHeader) {

        if (!user.getTenantDomain().equals(getTenantDomain(associatedUserRequestHeader))) {
            if (log.isDebugEnabled()) {
                log.debug("Provided associated user: " + associatedUserRequestHeader + ", " +
                        "has a different tenant domain to the authenticated user's tenant domain: "
                        + user.getTenantDomain());
            }
            return null;
        }
        return User.getUserFromUserName(associatedUserRequestHeader);
    }

    private void setAssociatedUserInCarbonContext(User user, User associatedUser,
                                                  AuthenticationResult authenticationResult) {

        UserAccountConnector userAccountConnector = AuthenticationServiceHolder.getInstance().getUserAccountConnector();
        if (userAccountConnector == null) {
            log.error("Unable to get the UserAccountConnector service");
            setFailedAuthentication(authenticationResult);
            return;
        }

        if (!hasValidAssociation(user, associatedUser, userAccountConnector)) {
            log.error("Associated user: " + associatedUser.toFullQualifiedUsername() + ", sent with the " +
                    "header: " + ASSOCIATED_USER_ID_HEADER + ", does not have a valid association with the " +
                    "user: " + user.toFullQualifiedUsername());
            setFailedAuthentication(authenticationResult);
            return;
        }

        if (log.isDebugEnabled()) {
            log.debug("Setting the Associated user: " + associatedUser.toFullQualifiedUsername()
                    + ", sent with the header: " + ASSOCIATED_USER_ID_HEADER + ", in the carbon " +
                    "context since it is a valid association of the user: " + user.toFullQualifiedUsername());
        }
        setUserInCarbonContext(MultitenantUtils.getTenantAwareUsername(associatedUser.toFullQualifiedUsername()));
    }

    private boolean hasValidAssociation(User user, User associatedUser, UserAccountConnector userAccountConnector) {

        try {
            UserAccountAssociationDTO[] userAccountAssociations = userAccountConnector.getAccountAssociationsOfUser(
                    user.toFullQualifiedUsername());
            for (UserAccountAssociationDTO userAccountAssociation : userAccountAssociations) {
                if (associatedUser.equals(getUser(userAccountAssociation))) {
                    return true;
                }
            }
        } catch (UserAccountAssociationException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while getting account associations of the user: " + user.toFullQualifiedUsername(),
                        e);
            }
        }
        return false;
    }

    private void setFailedAuthentication(AuthenticationResult authenticationResult) {

        authenticationResult.setAuthenticationStatus(AuthenticationStatus.FAILED);
    }

    private User getUser(UserAccountAssociationDTO userAccountAssociationDTO) {

        User user = new User();
        user.setTenantDomain(userAccountAssociationDTO.getTenantDomain());
        user.setUserStoreDomain(userAccountAssociationDTO.getDomain());
        user.setUserName(userAccountAssociationDTO.getUsername());
        return user;
    }

    private void setUserInCarbonContext(String domainAwareUserName) {

        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(domainAwareUserName);
    }
}
