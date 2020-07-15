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

package org.wso2.carbon.identity.cors.valve.exception;

import org.wso2.carbon.identity.cors.valve.constant.ErrorMessages;

/**
 * CORSException class.
 */
public class CORSException extends Exception {

    /**
     * The error code.
     */
    private int httpStatusCode;

    /**
     * Constructor with {@code message} and {@code errorCode} parameters.
     *
     * @param message        Message to be included in the exception.
     * @param httpStatusCode Error code of the exception.
     */
    public CORSException(String message, int httpStatusCode) {

        super(message);
        this.httpStatusCode = httpStatusCode;
    }

    /**
     * Constructor with {@code message}, {@code errorCode} and {@code cause} parameters.
     *
     * @param message        Message to be included in the exception.
     * @param httpStatusCode Error code of the exception.
     * @param cause          Exception to be wrapped.
     */
    public CORSException(String message, int httpStatusCode, Throwable cause) {

        super(message, cause);
        this.httpStatusCode = httpStatusCode;
    }

    /**
     * Constructor with the {@code errorMessage} parameter.
     *
     * @param errorMessage The error message.
     */
    public CORSException(ErrorMessages errorMessage) {

        this(errorMessage.getMessage(), errorMessage.getHttpStatusCode());
    }

    /**
     * Constructor with {@code errorMessage} and {@code cause} parameters.
     *
     * @param errorMessage The error message.
     */
    public CORSException(ErrorMessages errorMessage, Throwable cause) {

        this(errorMessage.getMessage(), errorMessage.getHttpStatusCode(), cause);
    }

    /**
     * Get the {@code errorCode}.
     *
     * @return The {@code errorCode}.
     */
    public int getHttpStatusCode() {

        return httpStatusCode;
    }
}
