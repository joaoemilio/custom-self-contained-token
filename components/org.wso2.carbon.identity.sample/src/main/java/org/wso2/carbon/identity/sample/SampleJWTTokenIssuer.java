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

package org.wso2.carbon.identity.sample;

import com.google.gson.JsonElement;
import com.nimbusds.jwt.JWTClaimsSet;
import net.minidev.json.JSONArray;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.JWTTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

/**
 * Self contained access token builder.
 */
public class SampleJWTTokenIssuer extends JWTTokenIssuer {

    private static final Log log = LogFactory.getLog(SampleJWTTokenIssuer.class);

    public SampleJWTTokenIssuer() throws IdentityOAuth2Exception {

        super();
    }

    /**
     * Populate custom claims (For implicit grant)
     *
     * @param jwtClaimsSet
     * @param tokenReqMessageContext
     * @throws IdentityOAuth2Exception
     */
    protected void handleCustomClaims(JWTClaimsSet jwtClaimsSet,
                                      OAuthTokenReqMessageContext tokenReqMessageContext) throws IdentityOAuth2Exception {

        super.handleCustomClaims(jwtClaimsSet, tokenReqMessageContext);
        removeDomainFromRoles(jwtClaimsSet);
    }

    /**
     * Populate custom claims
     *
     * @param jwtClaimsSet
     * @param authzReqMessageContext
     * @throws IdentityOAuth2Exception
     */
    protected void handleCustomClaims(JWTClaimsSet jwtClaimsSet,
                                      OAuthAuthzReqMessageContext authzReqMessageContext) throws IdentityOAuth2Exception {

        super.handleCustomClaims(jwtClaimsSet, authzReqMessageContext);
        removeDomainFromRoles(jwtClaimsSet);
    }

    private void removeDomainFromRoles(JWTClaimsSet jwtClaimsSet) {

        Object roles = jwtClaimsSet.getCustomClaim("role");
        if (roles instanceof JSONArray) {
            JSONArray rolesArray = (JSONArray) roles;
            int index = 0;
            for (Object role : rolesArray) {
                if(role instanceof String && ((String) role).contains("/")) {
                    String[] splittedRole = ((String) role).split("/");
                    if(!"Application".equalsIgnoreCase(splittedRole[0]) && !"Internal".equalsIgnoreCase
                            (splittedRole[0])) {
                        rolesArray.remove(index);
                        rolesArray.add(index, splittedRole[1]);
                    }
                    index ++;
                }
            }
        }

    }
}
