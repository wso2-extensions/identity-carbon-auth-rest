package org.wso2.carbon.identity.auth.valve.util;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.wso2.carbon.identity.auth.service.AuthenticationManager;
import org.wso2.carbon.identity.auth.service.factory.AuthenticationRequestBuilderFactory;
import org.wso2.carbon.identity.auth.service.handler.HandlerManager;
import org.wso2.carbon.identity.auth.valve.internal.AuthenticationValveServiceHolder;

import java.util.List;

public class AuthHandlerManager {
    private static AuthHandlerManager authHandlerManager = new AuthHandlerManager();

    private AuthHandlerManager() {

    }

    public static AuthHandlerManager getInstance() {
        return AuthHandlerManager.authHandlerManager;
    }

    public AuthenticationManager getAuthenticationManager() {
        List<AuthenticationManager> authenticationManagers = AuthenticationValveServiceHolder.getInstance()
                .getAuthenticationManagers();
        AuthenticationManager authenticationManager = HandlerManager.getInstance().getFirstPriorityHandler
                (authenticationManagers, true);
        return authenticationManager;
    }

    public AuthenticationRequestBuilderFactory getRequestBuilder(Request request, Response response){

        AuthenticationRequestBuilderFactory  requestBuilderFactory = null ;
        List<AuthenticationRequestBuilderFactory> requestBuilderFactories = AuthenticationValveServiceHolder
                .getInstance().getRequestBuilderFactories();
        for (AuthenticationRequestBuilderFactory requestBuilderFactoryTmp :requestBuilderFactories){
            if(requestBuilderFactoryTmp.canHandle(request, response)){
                requestBuilderFactory = requestBuilderFactoryTmp ;
                break ;
            }
        }
        return requestBuilderFactory ;

    }
}
