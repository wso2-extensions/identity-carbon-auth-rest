/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.auth.valve.util;

import org.apache.catalina.connector.Response;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONObject;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import org.slf4j.MDC;

/**
 * APIErrorResponseHandler handles the authentications and authorizations error responses.
 */
public class APIErrorResponseHandler {

    private static final Log log = LogFactory.getLog(APIErrorResponseHandler.class);

    private static final String AUTH_HEADER_NAME = "WWW-Authenticate";
    private static final String CORRELATION_ID_MDC = "Correlation-ID";
    private static final String BAD_REQUEST_ERROR_MSG = "Your client has issued a malformed or illegal request.";
    private static final String UNAUTHORIZED_ERROR_MSG = "Authorization failure. Authorization information was" +
            " invalid or missing from your request.";
    private static final String FORBIDDEN_ERROR_MSG = "Operation is not permitted. You do not have permissions to " +
            "make this request.";

    private static final String ADD_REALM_USER_CONFIG = "RestApiAuthentication.AddRealmUserToError";

    private static final boolean addRealmUser = parseAddRealmUser();

    /**
     * Generate the error response according to the relevant API endpoint and the HTTP status.
     */
    public static void handleErrorResponse(AuthenticationContext authenticationContext, Response response, int error,
                                            Exception e) throws IOException {

        if (log.isDebugEnabled() && e != null) {
            log.debug("Authentication Error ", e);
        }
        if (error == HttpServletResponse.SC_UNAUTHORIZED) {
            response.setHeader(AUTH_HEADER_NAME, getRealmInfo());
        }
        else if (addRealmUser){
            StringBuilder value = new StringBuilder(16);
            value.append("realm user=\"");
            if (authenticationContext != null && authenticationContext.getUser() != null) {
                value.append(authenticationContext.getUser().getUserName());
            }
            value.append('\"');
            response.setHeader(AUTH_HEADER_NAME, value.toString());
        }
        if (response.getRequest() != null) {
            String uri = response.getRequest().getRequestURI();
            uri = removeTenantDetailFromURI(uri);
            if (isRequestFromScim2Api(uri)) { // handles only scim 2.0 API error responses.
                handleScim2ApiErrorResponse(response, error, e);
            } else if (isRequestFromDCREndpoint(uri)) {
                handleDCRApiErrorResponse(response, error, e);
            } else {
                handleErrorResponseForCommonAPIs(response, error, e);
            }
        } else { // if request is null, sending a common error message
            handleErrorResponseForCommonAPIs(response, error, e);
        }
    }

    private static String removeTenantDetailFromURI(String uri) {
        if (uri.startsWith("/t")) {
            String[] uriSplit = uri.split("/");
            StringBuilder builder = new StringBuilder();
            if (uriSplit.length > 3) {
                for (int i = 3; i < uriSplit.length; i++) {
                    builder.append('/');
                    builder.append(uriSplit[i]);
                }
                return builder.toString();
            }
        }
        return uri;
    }

    private static boolean isRequestFromScim2Api(String uri) {

        return StringUtils.isNotBlank(uri) && uri.startsWith("/scim2");
    }

    private static boolean isRequestFromDCREndpoint(String uri) {

        return StringUtils.isNotBlank(uri) && uri.startsWith("/api/identity/oauth2/dcr");
    }

    private static void handleScim2ApiErrorResponse(Response response, int error, Exception e) throws IOException {

        response.setStatus(error);
        response.setHeader("Content-Type","application/json;charset=UTF-8");
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("status", error);
        String errorDescription;
        if (HttpServletResponse.SC_BAD_REQUEST == error) {
            errorDescription =  BAD_REQUEST_ERROR_MSG;
            jsonObject.put("scimType", "invalidSyntax"); //scimType only available for 400 errors in the SCIM spec.
        } else if (HttpServletResponse.SC_UNAUTHORIZED == error) {
            errorDescription = UNAUTHORIZED_ERROR_MSG;
        } else { // Forbidden Error
            errorDescription = FORBIDDEN_ERROR_MSG;
        }
        jsonObject.put("status", error);
        if (e != null) {
            errorDescription = e.getMessage();
        }
        jsonObject.put("detail", errorDescription);
        JSONArray schemasJsonArray = new JSONArray();
        schemasJsonArray.put("urn:ietf:params:scim:api:messages:2.0:Error");
        jsonObject.put("schemas", schemasJsonArray);
        setResponseBody(response, jsonObject);
    }

    private static void handleDCRApiErrorResponse(Response response, int error, Exception e) throws IOException {

        response.setStatus(error);
        response.setHeader("Content-Type","application/json;charset=UTF-8");
        JSONObject jsonObject = new JSONObject();
        String errorDescription;
        if (HttpServletResponse.SC_BAD_REQUEST == error) {
            jsonObject.put("error", "invalid_client_metadata");
            if (e != null) {
                jsonObject.put("error_description", e.getMessage());
            }
            setResponseBody(response, jsonObject);
            return;
        } else if (HttpServletResponse.SC_UNAUTHORIZED == error) {
            response.setHeader(AUTH_HEADER_NAME, "Bearer");
            // Setting a customize error message since specification did not provide any message format for 401 errors.
            jsonObject.put("code", error);
            jsonObject.put("message", "Unauthorized");
            errorDescription = UNAUTHORIZED_ERROR_MSG;
        } else {
            // Setting a customize error message since specification did not provide any message format for 403 errors.
            jsonObject.put("code", error);
            jsonObject.put("message", "Forbidden");
            errorDescription = FORBIDDEN_ERROR_MSG;
        }
        if (e != null) {
            jsonObject.put("description", e.getMessage());
        } else {
            jsonObject.put("description", errorDescription);
        }
        if (isCorrelationIDPresent()) {
            jsonObject.put("traceId", MDC.get(CORRELATION_ID_MDC));
        }
        setResponseBody(response, jsonObject);
    }

    private static void handleErrorResponseForCommonAPIs(Response response, int error, Exception e) throws IOException {

        response.setStatus(error);
        response.setHeader("Content-Type","application/json;charset=UTF-8");
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("code", error);
        String errorMsg;
        String errorDescription;
        if (HttpServletResponse.SC_BAD_REQUEST == error) {
            errorMsg = "Bad Request";
            errorDescription = BAD_REQUEST_ERROR_MSG;
        } else if (HttpServletResponse.SC_UNAUTHORIZED == error) {
            errorMsg = "Unauthorized";
            errorDescription = UNAUTHORIZED_ERROR_MSG;
        } else { // error == 403
            errorMsg = "Forbidden";
            errorDescription = FORBIDDEN_ERROR_MSG;
        }
        jsonObject.put("message", errorMsg);
        if (e != null) {
            jsonObject.put("description", e.getMessage());
        } else {
            jsonObject.put("description", errorDescription);
        }
        if (isCorrelationIDPresent()) {
            jsonObject.put("traceId", MDC.get(CORRELATION_ID_MDC));
        }
        setResponseBody(response, jsonObject);
    }

    private static void setResponseBody(Response response, JSONObject jsonObject) throws IOException {

        response.getWriter().write(jsonObject.toString(2));
        response.finishResponse();
    }

    private static boolean isCorrelationIDPresent() {

        return MDC.get(CORRELATION_ID_MDC) != null;
    }

    private static String getRealmInfo() {

        return "Bearer realm=" + ServerConfiguration.getInstance().getFirstProperty("HostName");
    }

    private static boolean parseAddRealmUser() {

        return Boolean.parseBoolean(IdentityUtil.getProperty(ADD_REALM_USER_CONFIG));
    }
}
