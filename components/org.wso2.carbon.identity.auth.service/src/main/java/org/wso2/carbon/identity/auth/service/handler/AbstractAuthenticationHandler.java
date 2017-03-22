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
import org.wso2.carbon.identity.common.base.handler.AbstractMessageHandler;
import org.wso2.carbon.identity.common.base.message.MessageContext;
import org.wso2.carbon.identity.mgt.RealmService;

import java.util.Locale;

/**
 * Abstract class for custom authentication handlers.
 *
 * The custom handlers should implement the doAuthenticate() method and optionally the postAuthenticate() method.
 *
 */
public abstract class AbstractAuthenticationHandler extends AbstractMessageHandler implements AuthenticationHandler {

    private RealmService realmService;

    @Override
    public final AuthenticationResult authenticate(MessageContext messageContext)
            throws AuthServerException, AuthClientException {

        AuthenticationResult authenticationResult = this.doAuthenticate(messageContext);
        postAuthenticate(messageContext, authenticationResult);

        return authenticationResult;

    }

    @Override
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
     * @param userName The primary User Identifier.
     * @return The User, Domain pair. Domain can be null.
     */
    protected ImmutablePair<String, String> decodeDomainAndUserName(String userName) {
        String domainName = null;
        if (userName != null && userName.contains("/")) {
            int lastAt = userName.lastIndexOf('/');
            domainName = userName.substring(0, lastAt);
            userName = userName.substring(lastAt + 1);
        }
        if (domainName != null) {
            domainName = domainName.toLowerCase(Locale.getDefault());
        }
        return new ImmutablePair(userName, domainName);
    }

    /**
     * Returns the authorization header type this authentication handler can handle.
     *
     * @return The HTTP authorization Header e.g. Basic
     */
    protected abstract String getAuthorizationHeaderType();

    /**
     *
     * This is where the actual authentication takes place.
     *
     * @param messageContext The message context to be carried forward.
     * @return the result holding the authentication flow.
     * @throws AuthServerException when there is an error in the request processing.
     * @throws AuthClientException when there is an error in the request itself.
     */
    protected abstract AuthenticationResult doAuthenticate(MessageContext messageContext)
            throws AuthServerException, AuthClientException;

    /**
     * Post authenticate hook.
     *
     * A custom authentication handler can provide its own implementation for the hook.
     *
     * @param messageContext  The message context to be carried forward.
     * @param authenticationResult The result of the authentication flow to be processed in post authentication.
     */
    protected void postAuthenticate(MessageContext messageContext, AuthenticationResult authenticationResult) {

    }

    @Override
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
