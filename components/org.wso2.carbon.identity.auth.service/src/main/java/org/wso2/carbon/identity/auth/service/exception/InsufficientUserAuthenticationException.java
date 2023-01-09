package org.wso2.carbon.identity.auth.service.exception;

import java.util.List;

public class InsufficientUserAuthenticationException extends AuthenticationFailException {

    private final List<String> requiredAcrValues;

    public InsufficientUserAuthenticationException(List<String> requiredAcrValues) {

        super();
        this.requiredAcrValues = requiredAcrValues;
    }

    public InsufficientUserAuthenticationException(String message, List<String> requiredAcrValues) {

        super(message);
        this.requiredAcrValues = requiredAcrValues;
    }

    public InsufficientUserAuthenticationException(String message, Throwable cause, List<String> requiredAcrValues) {

        super(message, cause);
        this.requiredAcrValues = requiredAcrValues;
    }

    public InsufficientUserAuthenticationException(Throwable cause, List<String> requiredAcrValues) {

        super(cause);
        this.requiredAcrValues = requiredAcrValues;
    }

    protected InsufficientUserAuthenticationException(String message, Throwable cause, boolean enableSuppression, boolean
            writableStackTrace, List<String> requiredAcrValues) {

        super(message, cause, enableSuppression, writableStackTrace);
        this.requiredAcrValues = requiredAcrValues;
    }

    public List<String> getRequiredAcrValues() {
        return requiredAcrValues;
    }
}
