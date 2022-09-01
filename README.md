#identity-carbon-auth-rest

## Custom Header Filter
Custom Header Filter to add customer headers for applications using the resource manager service. 

### Setting-up Guide
1. Setup WSO2 Identity Server and enable **Configuration Manager**
   
   https://is.docs.wso2.com/en/latest/develop/using-the-configuration-management-rest-apis/
  
2. Build the project and copy `org.wso2.carbon.identity.custom.header.filter-${project.version}.jar` to the
   `<IS_HOME>/repository/components/dropins` directory.

3. Open `deployment.toml` and enable the CustomHeaderFilter by adding following lines
   ```
      [custom_header_filter]
      enable = true
   ```

4. Create custom header configurations through the **Configuration Manager API**.

    1. Enable the Custom Header Filter by adding the resource type `custom-headers`.
    ```
    curl -k -X POST https://localhost:9443/api/identity/config-mgt/v1.0/resource-type \
       -H "accept: application/json" -H 'Content-Type: application/json' \
       -H 'Authorization: Basic YWRtaW46YWRtaW4=' \
       -d '{"name": "custom-headers", "description": "This is the resource type for custom header resources."}'
    ```
   
   2. Create a new app along with headers to be written.
    
   e.g Create a header named `Content-Security` for the application `wso2app`.
   ```
   curl -k -X POST https://localhost:9443/api/identity/config-mgt/v1.0/resource/custom-headers \
       -H "accept: application/json" -H 'Content-Type: application/json' \
       -H 'Authorization: Basic YWRtaW46YWRtaW4=' \
       -d '{"name": "wso2app","attributes": [{"key":"Content-Security", "value":"values"}]}'
   ```
   
   3. You can add headers to an existing app as follows.
   
   e.g Add headers to the existing `wso2app` app.
   ```
   curl -k -X POST https://localhost:9443/api/identity/config-mgt/v1.0/resource/custom-headers/wso2app \
        -H "accept: application/json" -H 'Content-Type: application/json' -H 'Authorization: Basic YWRtaW46YWRtaW4=' \
        -d '{"key":"Content-Security-Policy", "value":"values"}'
   ```