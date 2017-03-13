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

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.http.HttpHeaders;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.exception.AuthClientException;
import org.wso2.carbon.identity.auth.service.exception.AuthServerException;
import org.wso2.carbon.identity.auth.service.exception.AuthenticationFailException;
import org.wso2.carbon.identity.common.base.handler.AbstractMessageHandler;
import org.wso2.carbon.identity.common.base.message.MessageContext;
import org.wso2.carbon.identity.mgt.RealmService;

import java.util.Locale;

/**
 * This is the abstract class for custom authentication handlers.
 *
 * The custom handlers should implement the doAuthenticate() method and optionally the postAuthenticate() method.
 *
 */
public abstract class AbstractAuthenticationHandler extends AbstractMessageHandler implements AuthenticationHandler {

    private RealmService realmService;

    @Override
    public final AuthenticationResult authenticate(MessageContext messageContext)
            throws AuthServerException, AuthenticationFailException, AuthClientException {

        AuthenticationResult authenticationResult = this.doAuthenticate(messageContext);
        postAuthenticate(messageContext, authenticationResult);

        return authenticationResult;

    }

    public boolean isEnabled(MessageContext messageContext) {
        if (messageContext instanceof AuthenticationContext) {
            AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;
            if (authenticationContext.getAuthenticationRequest() != null) {
                String authorizationHeader = authenticationContext.getAuthenticationRequest().
                        getHeader(HttpHeaders.AUTHORIZATION);
                if (StringUtils.isNotEmpty(authorizationHeader) && authorizationHeader
                        .startsWith(getAuthorizationHeaderType())) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Returns the domain name from the user string.
     * @param userName
     * @return
     */
    protected ImmutablePair<String, String> decodeTenantDomainAndUserName(String userName) {
        String domainName = null;
        if(userName != null && userName.contains("/") ) {
            int lastAt = userName.lastIndexOf('/');
            domainName = userName.substring(0,lastAt);
            userName = userName.substring(lastAt + 1);
        }
        if(domainName != null) {
            domainName = domainName.toLowerCase(Locale.getDefault());
        }
        if(domainName == null) {
            domainName = "PRIMARY";
        }
        return new ImmutablePair(userName, domainName);
    }

    /**
     * Returns the authorization header type this authentication handler can handle.
     *
     * @return
     */
    protected abstract String getAuthorizationHeaderType();

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
    protected abstract AuthenticationResult doAuthenticate(MessageContext messageContext)
            throws AuthServerException, AuthenticationFailException, AuthClientException;

    /**
     *
     * This is the post authenticate hook.
     *
     * A custom authentication handler can provide its own implementation for the hook.
     *
     *
     * @param messageContext
     */
    protected void postAuthenticate(MessageContext messageContext, AuthenticationResult authenticationResult) {

//        AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;
//
//        if (AuthenticationStatus.SUCCESS.equals(authenticationResult.getAuthenticationStatus())) {
//
//            User user = authenticationContext.getUser();
//            if (user != null) {
//              // Set the user in to the Carbon context if the user belongs to same tenant. Skip this for cross tenant
//              // scenarios.
//
//            if (user.getTenantDomain() != null && user.getTenantDomain().equalsIgnoreCase(PrivilegedCarbonContext
//                    .getThreadLocalCarbonContext().getTenantDomain())) {
//                PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername(IdentityUtil.addDomainToName
//                        (user.getUserName(), user.getUserStoreDomain()));
//            }
//            }
//        }
    }

    public void setRealmService(RealmService realmService) {
        this.realmService = realmService;
    }

    /**
     * Returns the realm service which has been set.
     * @return The Realm service if already set. Null if not set.
     */
    protected RealmService getRealmService() {
        return this.realmService;
    }
}
