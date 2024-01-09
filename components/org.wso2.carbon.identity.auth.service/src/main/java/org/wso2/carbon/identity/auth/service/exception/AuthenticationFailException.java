package org.wso2.carbon.identity.auth.service.exception;

public class AuthenticationFailException extends Exception{

    private String errorCode;

    public AuthenticationFailException() {
        super();
    }

    public AuthenticationFailException(String message) {
        super(message);
    }

    public AuthenticationFailException(String message, Throwable cause) {
        super(message, cause);
    }

    public AuthenticationFailException(Throwable cause) {
        super(cause);
    }

    public AuthenticationFailException(String errorCode, String message) {

        super(message);
        this.errorCode = errorCode;
    }

    protected AuthenticationFailException(String message, Throwable cause, boolean enableSuppression, boolean
            writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

    public String getErrorCode() {

        return errorCode;
    }
}
