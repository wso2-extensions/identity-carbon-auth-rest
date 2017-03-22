/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.auth.rest.test;

import org.wso2.carbon.identity.mgt.AuthenticationContext;
import org.wso2.carbon.identity.mgt.Group;
import org.wso2.carbon.identity.mgt.IdentityStore;
import org.wso2.carbon.identity.mgt.User;
import org.wso2.carbon.identity.mgt.bean.GroupBean;
import org.wso2.carbon.identity.mgt.bean.UserBean;
import org.wso2.carbon.identity.mgt.claim.Claim;
import org.wso2.carbon.identity.mgt.claim.MetaClaim;
import org.wso2.carbon.identity.mgt.exception.AuthenticationFailure;
import org.wso2.carbon.identity.mgt.exception.GroupNotFoundException;
import org.wso2.carbon.identity.mgt.exception.IdentityStoreException;
import org.wso2.carbon.identity.mgt.exception.UserNotFoundException;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;

public class MockIdentityStore implements IdentityStore {

    @Override
    public boolean isUserExist(List<Claim> userClaims, String domainName) throws IdentityStoreException {
        return false;
    }

    @Override
    public List<String> isUserExist(List<Claim> list) throws IdentityStoreException {
        return null;
    }

    @Override
    public User getUser(String uniqueUserId) throws IdentityStoreException, UserNotFoundException {
        return null;
    }

    @Override
    public User getUser(Claim claim) throws IdentityStoreException, UserNotFoundException {
        return null;
    }

    @Override
    public User getUser(Claim claim, String domainName) throws IdentityStoreException, UserNotFoundException {
        return null;
    }

    @Override
    public List<User> listUsers(int offset, int length) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<User> listUsers(int offset, int length, String domainName) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<User> listUsers(Claim claim, int offset, int length) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<User> listUsers(Claim claim, int offset, int length, String domainName) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<User> listUsers(MetaClaim metaClaim, String filterPattern, int offset, int length)
            throws IdentityStoreException {
        return null;
    }

    @Override
    public List<User> listUsers(MetaClaim metaClaim, String filterPattern, int offset, int length, String domainName)
            throws IdentityStoreException {
        return null;
    }

    @Override
    public List<User> listUsers(List<Claim> claims, int offset, int length) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<User> listUsers(List<Claim> claims, int offset, int length, String domainName)
            throws IdentityStoreException {
        return null;
    }

    @Override
    public boolean isGroupExist(List<Claim> list, String s) throws IdentityStoreException {
        return false;
    }

    @Override
    public Group getGroup(String uniqueGroupId) throws IdentityStoreException, GroupNotFoundException {
        return null;
    }

    @Override
    public Group getGroup(Claim claim) throws IdentityStoreException, GroupNotFoundException {
        return null;
    }

    @Override
    public Group getGroup(Claim claim, String domainName) throws IdentityStoreException, GroupNotFoundException {
        return null;
    }

    @Override
    public List<Group> listGroups(int offset, int length) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<Group> listGroups(int offset, int length, String domainName) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<Group> listGroups(Claim claim, int offset, int length) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<Group> listGroups(Claim claim, int offset, int length, String domainName)
            throws IdentityStoreException {
        return null;
    }

    @Override
    public List<Group> listGroups(MetaClaim metaClaim, String filterPattern, int offset, int length)
            throws IdentityStoreException {
        return null;
    }

    @Override
    public List<Group> listGroups(MetaClaim metaClaim, String filterPattern, int offset, int length, String domainName)
            throws IdentityStoreException {
        return null;
    }

    @Override
    public List<Group> getGroupsOfUser(String uniqueUserId) throws IdentityStoreException, UserNotFoundException {
        return null;
    }

    @Override
    public List<User> getUsersOfGroup(String uniqueGroupId) throws IdentityStoreException, GroupNotFoundException {
        return null;
    }

    @Override
    public boolean isUserInGroup(String uniqueUserId, String uniqueGroupId)
            throws IdentityStoreException, UserNotFoundException, GroupNotFoundException {
        return false;
    }

    @Override
    public List<Claim> getClaimsOfUser(String uniqueUserId) throws IdentityStoreException, UserNotFoundException {
        return null;
    }

    @Override
    public List<Claim> getClaimsOfUser(String uniqueUserId, List<MetaClaim> metaClaims)
            throws IdentityStoreException, UserNotFoundException {
        return null;
    }

    @Override
    public List<Claim> getClaimsOfGroup(String uniqueGroupId) throws IdentityStoreException, GroupNotFoundException {
        return null;
    }

    @Override
    public List<Claim> getClaimsOfGroup(String uniqueGroupId, List<MetaClaim> metaClaims)
            throws IdentityStoreException, GroupNotFoundException {
        return null;
    }

    @Override
    public User addUser(UserBean user) throws IdentityStoreException {
        return null;
    }

    @Override
    public User addUser(UserBean user, String domainName) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<User> addUsers(List<UserBean> users) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<User> addUsers(List<UserBean> users, String domainName) throws IdentityStoreException {
        return null;
    }

    @Override
    public void updateUserClaims(String uniqueUserId, List<Claim> claims)
            throws IdentityStoreException, UserNotFoundException {

    }

    @Override
    public void updateUserClaims(String uniqueUserId, List<Claim> claimsToAdd, List<Claim> claimsToRemove)
            throws IdentityStoreException, UserNotFoundException {

    }

    @Override
    public void updateUserCredentials(String uniqueUserId, List<Callback> credentials)
            throws IdentityStoreException, UserNotFoundException {

    }

    @Override
    public void updateUserCredentials(String uniqueUserId, List<Callback> credentialsToAdd,
            List<Callback> credentialsToRemove) throws IdentityStoreException, UserNotFoundException {

    }

    @Override
    public void deleteUser(String uniqueUserId) throws IdentityStoreException, UserNotFoundException {

    }

    @Override
    public void updateGroupsOfUser(String uniqueUserId, List<String> uniqueGroupIds) throws IdentityStoreException {

    }

    @Override
    public void updateGroupsOfUser(String uniqueUserId, List<String> uniqueGroupIdsToAdd,
            List<String> uniqueGroupIdsToRemove) throws IdentityStoreException {

    }

    @Override
    public Group addGroup(GroupBean groupBean) throws IdentityStoreException {
        return null;
    }

    @Override
    public Group addGroup(GroupBean groupBean, String domainName) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<Group> addGroups(List<GroupBean> groups) throws IdentityStoreException {
        return null;
    }

    @Override
    public List<Group> addGroups(List<GroupBean> groups, String domainName) throws IdentityStoreException {
        return null;
    }

    @Override
    public void updateGroupClaims(String uniqueGroupId, List<Claim> claims)
            throws IdentityStoreException, GroupNotFoundException {

    }

    @Override
    public void updateGroupClaims(String uniqueGroupId, List<Claim> claimsToAdd, List<Claim> claimsToRemove)
            throws IdentityStoreException, GroupNotFoundException {

    }

    @Override
    public void deleteGroup(String uniqueGroupId) throws IdentityStoreException, GroupNotFoundException {

    }

    @Override
    public void updateUsersOfGroup(String uniqueGroupId, List<String> uniqueUserIds) throws IdentityStoreException {

    }

    @Override
    public void updateUsersOfGroup(String uniqueGroupId, List<String> uniqueUserIdsToAdd,
            List<String> uniqueUserIdsToRemove) throws IdentityStoreException {

    }

    @Override
    public AuthenticationContext authenticate(Claim claim, Callback[] credentials, String domainName)
            throws AuthenticationFailure, IdentityStoreException {

        String userName = claim.getValue();
        if(userName != null && userName.contains("IdentityStoreException")) {
            throw new IdentityStoreException("Test with IdentityStoreException");
        }
        if (domainName == null) {
            domainName = this.getPrimaryDomainName();
        }
        Optional<Callback> callback = Arrays.stream(credentials).filter(c -> c instanceof PasswordCallback).findAny();
        if (callback.isPresent()) {
            String password = new String(((PasswordCallback) callback.get()).getPassword());
            if (password.equals(userName)) {
                return new AuthenticationContext(
                        new User.UserBuilder().setUserId(claim.getValue()).setIdentityStore(this)
                                //                            .setAuthorizationStore(IdentityMgtDataHolder.getInstance().getAuthorizationStore())
                                .setDomainName(domainName).build());
            }
        }

        throw new AuthenticationFailure("User name or password mismatch: " + userName);
    }

    @Override
    public String getPrimaryDomainName() throws IdentityStoreException {
        return "TEST";
    }

    @Override
    public Set<String> getDomainNames() throws IdentityStoreException {
        return null;
    }

    @Override
    public void setUserState(String uniqueUserId, String targetState)
            throws IdentityStoreException, UserNotFoundException {

    }
}

