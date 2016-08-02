package org.wso2.carbon.identity.auth.service.module;

public class ResourceConfigKey {

    private String contextPath;
    private String httpMethod;

    public ResourceConfigKey(String contextPath, String httpMethod) {
        this.contextPath = contextPath;
        this.httpMethod = httpMethod;
    }

    public String getContextPath() {
        return contextPath;
    }

    public void setContextPath(String contextPath) {
        this.contextPath = contextPath;
    }

    public String getHttpMethod() {
        return httpMethod;
    }

    public void setHttpMethod(String httpMethod) {
        this.httpMethod = httpMethod;
    }


    @Override
    public boolean equals(Object o) {
        if ( this == o ) return true;
        if ( o == null || getClass() != o.getClass() ) return false;

        ResourceConfigKey that = (ResourceConfigKey) o;
        if ( contextPath.trim().endsWith("*") ) {
            String contextPathRemovedRegEx = contextPath.trim().substring(0, contextPath.trim().length() - 1);
            if ( !that.contextPath.startsWith(contextPathRemovedRegEx) ) {
                return false;
            }
        } else if ( !contextPath.equals(that.contextPath) ) {
            return false;
        }

        if ( httpMethod.equalsIgnoreCase("all") )
            return true;
        return httpMethod.contains(that.httpMethod);

    }

    @Override
    public int hashCode() {
        int result = contextPath.hashCode();
        result = 31 * result + httpMethod.hashCode();
        return result;
    }
}
