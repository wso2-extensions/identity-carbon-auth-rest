/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.cors.valve.constant;

import javax.servlet.http.HttpServletResponse;

/**
 * ErrorMessages enum holds the error codes and messages.
 * COV stands for CORS Valve.
 */
public enum ErrorMessages {

    /**
     * CORS origin denied exception.
     */
    ERROR_CODE_ORIGIN_DENIED(HttpServletResponse.SC_FORBIDDEN,
            "CORS origin denied"),

    /**
     * Unsupported HTTP method.
     */
    ERROR_CODE_UNSUPPORTED_METHOD(HttpServletResponse.SC_METHOD_NOT_ALLOWED,
            "Unsupported HTTP method"),

    /**
     * Unsupported HTTP request header.
     */
    ERROR_CODE_UNSUPPORTED_REQUEST_HEADER(HttpServletResponse.SC_FORBIDDEN,
            "Unsupported HTTP request header"),

    /**
     * Invalid simple / actual request.
     */
    ERROR_CODE_INVALID_ACTUAL_REQUEST(HttpServletResponse.SC_BAD_REQUEST,
            "Invalid simple/actual CORS request"),

    /**
     * Invalid preflight request.
     */
    ERROR_CODE_INVALID_PREFLIGHT_REQUEST(HttpServletResponse.SC_BAD_REQUEST,
            "Invalid preflight CORS request"),

    /**
     * Missing Access-Control-Request-Method header.
     */
    ERROR_CODE_MISSING_ACCESS_CONTROL_REQUEST_METHOD_HEADER(HttpServletResponse.SC_BAD_REQUEST,
            "Invalid preflight CORS request: Missing Access-Control-Request-Method header"),

    /**
     * Invalid request header value.
     */
    ERROR_CODE_INVALID_HEADER_VALUE(HttpServletResponse.SC_BAD_REQUEST,
            "Invalid preflight CORS request: Bad request header value"),

    /**
     * Generic HTTP requests not allowed.
     */
    ERROR_CODE_GENERIC_HTTP_NOT_ALLOWED(HttpServletResponse.SC_FORBIDDEN,
            "Generic HTTP requests not allowed");

    /**
     * The error code.
     */
    private final int httpStatusCode;

    /**
     * The error message.
     */
    private final String message;

    /**
     * ErrorMessages constructor which takes the {@code code}, {@code message} and {@code description} as parameters.
     *
     * @param httpStatusCode The error code.
     * @param message        The error message.
     */
    ErrorMessages(int httpStatusCode, String message) {

        this.httpStatusCode = httpStatusCode;
        this.message = message;
    }

    /**
     * Get the {@code code}.
     *
     * @return The {@code code} to be set.
     */
    public int getHttpStatusCode() {

        return httpStatusCode;
    }

    /**
     * Get the {@code message}.
     *
     * @return The {@code message} to be set.
     */
    public String getMessage() {

        return message;
    }

    @Override
    public String toString() {

        return httpStatusCode + ":" + message;
    }
}
