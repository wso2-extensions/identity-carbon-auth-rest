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

import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.auth.service.exception.AuthClientException;
import org.wso2.carbon.identity.auth.service.exception.AuthenticationFailException;
import org.wso2.carbon.identity.auth.service.exception.AuthServerException;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.handler.AbstractIdentityMessageHandler;
import org.wso2.carbon.identity.core.handler.IdentityMessageHandler;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

/**
 * This is the abstract class for custom authentication handlers.
 *
 * The custom handlers should implement the doAuthenticate() method and optionally the postAuthenticate() method.
 *
 */
public abstract class AuthenticationHandler extends AbstractIdentityMessageHandler {


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
                    PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(IdentityUtil.addDomainToName
                            (user.getUserName(), user.getUserStoreDomain()));
                }
            }
        }
    }
}
