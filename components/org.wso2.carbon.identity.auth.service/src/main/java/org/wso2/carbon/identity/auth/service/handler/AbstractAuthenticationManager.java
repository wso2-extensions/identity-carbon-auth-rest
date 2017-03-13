/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.auth.service.handler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationManager;
import org.wso2.carbon.identity.common.base.handler.MessageHandlerComparator;
import org.wso2.carbon.identity.common.base.message.MessageContext;

import java.util.ArrayList;
import java.util.List;

/**
 * HandlerManager class can be used to get the correct handlers,
 * just before execute it either list or first priority one.
 */
public abstract class AbstractAuthenticationManager implements AuthenticationManager {

    private static Logger log = LoggerFactory.getLogger(AbstractAuthenticationManager.class);
    private List<AuthenticationHandler> authenticationHandlers = new ArrayList<>();

    /**
     * Adds AuthenticationHandler to the list of supported AuthenticationHandler (s).
     * @param authenticationHandler  The AuthenticationHandler to be added.
     */
    public void addAuthenticationHandler(AuthenticationHandler authenticationHandler) {
        List<AuthenticationHandler> copy = new ArrayList(authenticationHandlers);
        copy.add(authenticationHandler);
        copy.sort(new MessageHandlerComparator());
        authenticationHandlers = copy;
    }

    /**
     * Removes AuthenticationHandler from the list of supported AuthenticationHandler(s).
     *
     * @param authenticationHandler The AuthenticationHandler to be removed.
     */
    public void removeAuthenticationHandler(AuthenticationHandler authenticationHandler) {
        authenticationHandlers.remove(authenticationHandler);
    }

    /**
     * Get the first priority handler after sort and filter the enabled handlers for authentication.
     *
     * @param isEnableHandlersOnly
     * @return IdentityHandler
     */
    public AuthenticationHandler getFirstPriorityAuthenticationHandler(boolean isEnableHandlersOnly,
            AuthenticationContext authenticationContext) {
        return getFirstPriorityHandler(authenticationHandlers, isEnableHandlersOnly, authenticationContext);
    }

    /**
     * Get the first priority handler after sort and filter the enabled handlers.
     *
     * @param identityHandlers
     * @param isEnableHandlersOnly
     * @return IdentityHandler
     */
    public <T extends AuthenticationHandler> T getFirstPriorityHandler(List<T> identityHandlers,
            boolean isEnableHandlersOnly, MessageContext messageContext) {
        if (log.isDebugEnabled()) {
            log.debug("Get first priority handler for the given handler list.");
        }
        if (identityHandlers == null || identityHandlers.isEmpty()) {
            return null;
        }
        T identityHandler = null;

        for (T identityHandlerTmp : identityHandlers) {
            if (isEnableHandlersOnly) {
                if (identityHandlerTmp.isEnabled(messageContext)) {
                    identityHandler = identityHandlerTmp;
                    break;
                }
            } else {
                identityHandler = identityHandlerTmp;
                break;
            }
        }
        if (log.isDebugEnabled()) {
            if(identityHandler == null) {
                log.debug("Get first priority handler : returned null");
            } else {
                log.debug("Get first priority handler : " + identityHandler.getName() + "(" +
                        identityHandler.getClass().getName() + ")");
            }
        }
        return identityHandler;
    }
}
