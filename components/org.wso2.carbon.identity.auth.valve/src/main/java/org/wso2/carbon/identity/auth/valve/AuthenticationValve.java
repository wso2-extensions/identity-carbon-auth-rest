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

package org.wso2.carbon.identity.auth.valve;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.auth.service.AuthenticationManager;
import org.wso2.carbon.identity.auth.service.AuthenticationRequest;
import org.wso2.carbon.identity.auth.service.AuthenticationResult;
import org.wso2.carbon.identity.auth.service.AuthenticationStatus;
import org.wso2.carbon.identity.auth.service.exception.AuthClientException;
import org.wso2.carbon.identity.auth.service.exception.AuthRuntimeException;
import org.wso2.carbon.identity.auth.service.exception.AuthServerException;
import org.wso2.carbon.identity.auth.service.exception.AuthenticationFailException;
import org.wso2.carbon.identity.auth.service.module.ResourceConfig;
import org.wso2.carbon.identity.auth.service.module.ResourceConfigKey;
import org.wso2.carbon.identity.auth.valve.util.AuthHandlerManager;
import org.wso2.msf4j.Interceptor;
import org.wso2.msf4j.Request;
import org.wso2.msf4j.Response;
import org.wso2.msf4j.ServiceMethodInfo;

import java.io.IOException;
import javax.servlet.http.HttpServletResponse;


/**
 * AuthenticationValve can be used to intercept any request.
 */
public class AuthenticationValve implements Interceptor {

    private static final String AUTH_CONTEXT = "auth-context";
    private static final String AUTH_HEADER_NAME = "WWW-Authenticate";

    private static final Logger log = LoggerFactory.getLogger(AuthenticationValve.class);


    @Override
    public boolean preCall(Request request, Response response, ServiceMethodInfo serviceMethodInfo) throws Exception {
        AuthenticationManager authenticationManager = AuthHandlerManager.getInstance().getAuthenticationManager();
        ResourceConfig securedResource = authenticationManager.getSecuredResource(new ResourceConfigKey(request.getUri()
                                                                                , request.getHttpMethod()));
        if ( securedResource == null ) {
            return false;
        }

        if ( log.isDebugEnabled() ) {
            log.debug("AuthenticationValve hit on secured resource : " + request.getUri());
        }

        AuthenticationContext authenticationContext = null;
        AuthenticationResult authenticationResult = null;
        try {

            AuthenticationRequest.AuthenticationRequestBuilder authenticationRequestBuilder = AuthHandlerManager
                    .getInstance().getRequestBuilder(request, response).createRequestBuilder(request, response);
            authenticationContext = new AuthenticationContext(authenticationRequestBuilder.build());
            authenticationContext.setResourceConfig(securedResource);
            //Do authentication.
            authenticationResult = authenticationManager.authenticate(authenticationContext);

            AuthenticationStatus authenticationStatus = authenticationResult.getAuthenticationStatus();
            if ( authenticationStatus.equals(AuthenticationStatus.SUCCESS) ) {
                //Set the User object as an attribute for further references.
                request.setProperty(AUTH_CONTEXT, authenticationContext);

                return true;
            } else {
                handleErrorResponse(authenticationContext, response, HttpServletResponse.SC_UNAUTHORIZED);
            }
        } catch ( AuthClientException | AuthServerException e ) {
            handleErrorResponse(authenticationContext, response, HttpServletResponse.SC_BAD_REQUEST);
        } catch ( AuthenticationFailException | AuthRuntimeException e ) {
            handleErrorResponse(authenticationContext, response, HttpServletResponse.SC_UNAUTHORIZED);
        }
        return false;
    }

    private void handleErrorResponse(AuthenticationContext authenticationContext, Response response, int error) throws
            IOException {
        StringBuilder value = new StringBuilder(16);
        value.append("realm user=\"");
        if ( authenticationContext.getUser() != null ) {
            //TODO get username claim
            value.append(authenticationContext.getUser().getDomainName());
        }
        value.append('\"');
        response.setStatus(error);
        response.setHeader(AUTH_HEADER_NAME, value.toString());
        response.send();
    }


    @Override
    public void postCall(Request request, int i, ServiceMethodInfo serviceMethodInfo) throws Exception {

    }
}
