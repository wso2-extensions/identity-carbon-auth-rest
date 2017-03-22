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

package org.wso2.carbon.identity.auth.service;

import org.wso2.carbon.messaging.Header;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * AuthenticationResult holding the status of the authentication.
 */
public class AuthenticationResult {

    private AuthenticationStatus authenticationStatus = AuthenticationStatus.FAILED;
    private int statusCode = 0;
    private List<Header> responseHeaders;

    /**
     * Constructor taking the authentication status as the parameter.
     * @param authenticationStatus theAuthentication Status to return.
     */
    public AuthenticationResult(AuthenticationStatus authenticationStatus) {
        this.authenticationStatus = authenticationStatus;
    }

    public AuthenticationStatus getAuthenticationStatus() {
        return authenticationStatus;
    }

    public void setAuthenticationStatus(AuthenticationStatus authenticationStatus) {
        this.authenticationStatus = authenticationStatus;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public List<Header> getResponseHeaders() {
        return responseHeaders == null ? Collections.emptyList() : Collections.unmodifiableList(responseHeaders);
    }

    public void addResponseHeader(String name, String value) {
        if (responseHeaders == null) {
            responseHeaders = new ArrayList<>();
        }
        responseHeaders.add(new Header(name, value));
    }
}
