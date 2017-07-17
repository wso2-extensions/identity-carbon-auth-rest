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

package org.wso2.carbon.identity.authz.validation.valve;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class ValidationValve extends ValveBase {

    private static final String AUTHORIZATION_HEADER_NAME = "Authorization";
    private static final String AUTH_TYPE_BASIC = "Basic";
    private static final String CXF_HEADER_VALIDATION_CONTEXT = "CXFHeaderValidaton.Context";
    private static final int AUTH_TYPE_BASIC_LENGTH = "Basic".length();
    private static final int MINIMUM_CREDENTIAL_SIZE = 4;

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {

        String requestURI = request.getRequestURI();
        List<String> validationContexts = getConfigContexts();
        boolean requireValidation = false;

        //Get the validation contexts and check whether request URI contains any of them.
        if (validationContexts != null && StringUtils.isNotEmpty(requestURI)) {
            for (String context : validationContexts) {
                Pattern pattern = Pattern.compile(context);
                Matcher matcher = pattern.matcher(requestURI);
                if (matcher.find()) {
                    requireValidation = true;
                    break;
                }
            }
        }

        if (!requireValidation) {
            getNext().invoke(request, response);
            return;
        }

        String authHeader = request.getHeader(AUTHORIZATION_HEADER_NAME);
        if (StringUtils.isEmpty(authHeader)) {
            getNext().invoke(request, response);
            return;
        }
        String authType = null;
        if (authHeader.length() >= AUTH_TYPE_BASIC_LENGTH) {
            authType = authHeader.trim().substring(0, AUTH_TYPE_BASIC_LENGTH);
        }
        if (AUTH_TYPE_BASIC.equals(authType)) {
            String authCredentials = authHeader.trim().substring(AUTH_TYPE_BASIC_LENGTH);
            if (StringUtils.isBlank(authCredentials) || (authCredentials.substring(" ".length()).
                    indexOf(' ') >= 0) || authCredentials.trim().length() < MINIMUM_CREDENTIAL_SIZE) {
                String errorMsg = "Internal Server Error";
                handleErrorResponse(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, errorMsg);
            } else {
                getNext().invoke(request, response);
            }
        } else {
            getNext().invoke(request, response);
        }
    }


    private List<String> getConfigContexts() {

        List<String> configContexts = null;
        Map<String, Object> configuration = IdentityConfigParser.getInstance().getConfiguration();
        Object validationContexts = configuration.get(CXF_HEADER_VALIDATION_CONTEXT);
        if (validationContexts != null) {
            if (validationContexts instanceof ArrayList) {
                configContexts = (ArrayList<String>) validationContexts;
            } else {
                configContexts = new ArrayList<>();
                configContexts.add(validationContexts.toString());
            }
        }
        return configContexts;
    }

    private void handleErrorResponse(Response response, int error, String errorMsg) throws IOException {

        response.setStatus(error);
        response.setCharacterEncoding("UTF-8");
        response.getWriter().print(errorMsg);
    }
}
