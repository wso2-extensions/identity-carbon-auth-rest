/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.exception.AuthClientException;
import org.wso2.carbon.identity.auth.service.exception.AuthServerException;
import org.wso2.carbon.identity.common.base.handler.MessageHandler;
import org.wso2.carbon.identity.common.base.message.MessageContext;
import org.wso2.carbon.identity.mgt.RealmService;

/**
 * Authentication handler for the services, and interceptors.
 */
public interface AuthenticationHandler extends MessageHandler {

    /**
     * Authenticate the message. Called by the authentication framework.
     *
     * @param messageContext The message context.
     * @return The authentication result.
     * @throws AuthServerException  When there is a internal server exception
     * @throws AuthClientException When there is a logical exception in authentication.
     */
    AuthenticationResult authenticate(MessageContext messageContext) throws AuthServerException, AuthClientException;

    /**
     * Sets the realm service for the authentication handler.
     * @param realmService the RealmService to be used to access Identity Store.
     */
    void setRealmService(RealmService realmService);
}
