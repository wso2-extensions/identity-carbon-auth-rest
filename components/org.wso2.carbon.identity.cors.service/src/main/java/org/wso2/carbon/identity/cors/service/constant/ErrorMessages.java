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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.cors.service.constant;

/**
 * ErrorMessages enum holds the error codes and messages.
 * CMS stands for Cors Management Service.
 */
public enum ErrorMessages {

    /**
     * Stored origin is invalid.
     */
    ERROR_CODE_INVALID_STORED_ORIGIN("65001",
            "The stored origin is invalid.",
            "Server encountered an error validating the stored origin %s."),

    /**
     * Invalid Origin.
     */
    ERROR_CODE_INVALID_ORIGIN("60001",
            "Invalid CORS origin",
            "%s is not a valid CORS origin.");

    /**
     * The error prefix.
     */
    private static final String ERROR_PREFIX = "COS";

    /**
     * The error code.
     */
    private final String code;

    /**
     * The error message.
     */
    private final String message;

    /**
     * The error description.
     */
    private final String description;

    /**
     * ErrorMessages constructor which takes the {@code code}, {@code message} and {@code description} as parameters.
     *
     * @param code        The error code.
     * @param message     The error message.
     * @param description The error description. Could be null where unnecessary.
     */
    ErrorMessages(String code, String message, String description) {

        this.code = ERROR_PREFIX +  "-" + code;
        this.message = message;
        this.description = description;
    }

    /**
     * Get the {@code code}.
     *
     * @return Returns the {@code code} to be set.
     */
    public String getCode() {

        return code;
    }

    /**
     * Get the {@code message}.
     *
     * @return Returns the {@code message} to be set.
     */
    public String getMessage() {

        return message;
    }

    /**
     * Get the {@code description}.
     *
     * @return Returns the {@code description} to be set.
     */
    public String getDescription() {

        return description;
    }

    @Override
    public String toString() {

        return code + ":" + message;
    }
}
