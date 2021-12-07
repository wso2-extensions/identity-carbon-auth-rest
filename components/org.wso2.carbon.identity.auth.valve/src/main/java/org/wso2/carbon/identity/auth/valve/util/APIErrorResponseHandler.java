package org.wso2.carbon.identity.auth.valve.util;

import org.apache.catalina.connector.Response;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.JSONArray;
import org.json.JSONObject;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import org.apache.log4j.MDC;

public class APIErrorResponseHandler {

    private static final Log log = LogFactory.getLog(APIErrorResponseHandler.class);

    private static final String AUTH_HEADER_NAME = "WWW-Authenticate";
    private static final String CORRELATION_ID_MDC = "Correlation-ID";

    public static void handleErrorResponse(AuthenticationContext authenticationContext, Response response, int error,
                                            Exception e) throws IOException {

        if (log.isDebugEnabled() && e != null) {
            log.debug("Authentication Error ", e);
        }
        StringBuilder value = new StringBuilder(16);
        value.append("realm user=\"");
        if (authenticationContext != null && authenticationContext.getUser() != null) {
            value.append(authenticationContext.getUser().getUserName());
        }
        value.append('\"');
        response.setHeader(AUTH_HEADER_NAME, value.toString());
        if (isRequestFromScim2Api(response)) { // handles only scim 2.0 API error responses.
            handleScim2ApiErrorResponse(response, error, e);
        } else if (isRequestFromDCREndpoint(response)) {
            handleDCRApiErrorResponse(response, error, e);
        } else {
            handleErrorResponseForCommonAPIs(response, error, e);
        }
    }


    private static boolean isRequestFromScim2Api(Response response) {

        if (response.getRequest() == null) {
            return false;
        }
        return response.getRequest().getRequestURI().contains("/scim2");
    }

    private static boolean isRequestFromDCREndpoint(Response response) {
        if (response.getRequest() == null) {
            return false;
        }
        return response.getRequest().getRequestURI().contains("/dcr");
    }

    private static void handleScim2ApiErrorResponse(Response response, int error, Exception e) throws IOException {

        response.setStatus(error);
        response.setHeader("Content-Type","application/json;charset=UTF-8");
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("status", error);
        String errorDescription;
        if (HttpServletResponse.SC_BAD_REQUEST == error) {
            errorDescription =  "Request is unparsable, syntactically incorrect, or violates schema.";
            jsonObject.put("scimType", "invalidSyntax"); //scimType only available for 400 errors in the SCIM spec.
        } else if (HttpServletResponse.SC_UNAUTHORIZED == error) {
            errorDescription = "Authorization failure. The authorization header is invalid or missing.";
        } else { // Forbidden Error
            errorDescription = "Operation is not permitted based on the supplied authorization.";
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
            errorDescription = "Authorization failure. The authorization header is invalid or missing.";
        } else {
            // Setting a customize error message since specification did not provide any message format for 403 errors.
            jsonObject.put("code", error);
            jsonObject.put("message", "Forbidden");
            errorDescription = "Operation is not permitted based on the supplied authorization.";
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
            errorDescription = "Request is unparsable, syntactically incorrect, or violates schema.";
        } else if (HttpServletResponse.SC_UNAUTHORIZED == error) {
            errorMsg = "Unauthorized";
            errorDescription = "Authorization failure. The authorization header is invalid or missing.";
        } else { // error == 403
            errorMsg = "Forbidden";
            errorDescription = "Operation is not permitted based on the supplied authorization.";
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

    public static boolean isCorrelationIDPresent() {
        return MDC.get(CORRELATION_ID_MDC) != null;
    }
}
