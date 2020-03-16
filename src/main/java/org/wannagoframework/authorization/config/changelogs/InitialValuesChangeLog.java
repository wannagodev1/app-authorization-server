/*
 * This file is part of the WannaGo distribution (https://github.com/wannago).
 * Copyright (c) [2019] - [2020].
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */


package org.wannagoframework.authorization.config.changelogs;

import com.github.mongobee.changeset.ChangeLog;
import com.github.mongobee.changeset.ChangeSet;
import java.util.Collections;
import java.util.List;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.wannagoframework.authorization.config.AppProperties;
import org.wannagoframework.authorization.config.AppProperties.Auth.ClientAuth;
import org.wannagoframework.authorization.domain.AuthProviderEnum;
import org.wannagoframework.authorization.domain.SecurityClient;
import org.wannagoframework.authorization.domain.SecurityRole;
import org.wannagoframework.authorization.domain.SecurityUser;
import org.wannagoframework.authorization.domain.SecurityUserTypeEnum;
import org.wannagoframework.commons.utils.SpringApplicationContext;

@Component
@ChangeLog
public class InitialValuesChangeLog {

  private PasswordEncoder userPasswordEncoder = new BCryptPasswordEncoder(10);
  private PasswordEncoder clientPasswordEncoder = new BCryptPasswordEncoder(4);

  @ChangeSet(order = "001", id = "insertBrowserClientDetails", author = "Wanna Go Dev1")
  public void insertBrowserClientDetails(MongoTemplate mongoTemplate) {
    SecurityClient browserClientDetails = new SecurityClient();
    browserClientDetails.setClientId("browser");
    browserClientDetails.setClientSecret(clientPasswordEncoder.encode("1234"));
    browserClientDetails.setScopes("ui");
    browserClientDetails.setGrantTypes("refresh_token,password");

    mongoTemplate.save(browserClientDetails);
  }

  @ChangeSet(order = "002", id = "insertDefaultRoles", author = "Wanna Go Dev1")
  public void insertDefaultRoles(MongoTemplate mongoTemplate) {
    SecurityRole externalUserRole = new SecurityRole();
    externalUserRole.setCanLogin(true);
    externalUserRole.setName("EXTERNAL");
    externalUserRole.setDescription("For external users");
    mongoTemplate.save(externalUserRole);

    SecurityRole adminUserRole = new SecurityRole();
    adminUserRole.setCanLogin(true);
    adminUserRole.setName("ADMIN");
    adminUserRole.setDescription("For administrator users");
    mongoTemplate.save(adminUserRole);

    SecurityRole i18nUserRole = new SecurityRole();
    i18nUserRole.setCanLogin(true);
    i18nUserRole.setName("I18N");
    i18nUserRole.setDescription("For user to handle I18N");
    mongoTemplate.save(i18nUserRole);

    SecurityRole internalUserRole = new SecurityRole();
    internalUserRole.setCanLogin(false);
    internalUserRole.setName("INTERNAL");
    internalUserRole.setDescription("For internal users (System)");
    mongoTemplate.save(internalUserRole);
  }

  @ChangeSet(order = "003", id = "insertSystemUserAuthentication", author = "Wanna Go Dev1")
  public void insertSystemUserAuthentication(MongoTemplate mongoTemplate) {
    SecurityRole adminRole = mongoTemplate
        .findOne(Query.query(Criteria.where("name").is("ADMIN")), SecurityRole.class);

    SecurityUser securityUser = new SecurityUser();
    securityUser.setIsActivated(true);
    securityUser.setUserType(SecurityUserTypeEnum.ADMIN);
    securityUser.setRoles(Collections.singleton(adminRole));
    securityUser.setPassword(userPasswordEncoder.encode("1234"));
    securityUser.setUsername("System");
    securityUser.setProvider(AuthProviderEnum.LOCAL);
    mongoTemplate.save(securityUser);
  }

  @ChangeSet(order = "004", id = "insertFrontofficeServiceClientDetails", author = "Wanna Go Dev1")
  public void insertFrontofficeServiceClientDetails(MongoTemplate mongoTemplate) {
    SecurityClient frontofficeServiceClientDetails = new SecurityClient();
    frontofficeServiceClientDetails.setClientId("frontend-application");
    frontofficeServiceClientDetails.setClientSecret(clientPasswordEncoder.encode("1234"));
    frontofficeServiceClientDetails.setScopes("frontend");
    frontofficeServiceClientDetails.setGrantTypes("refresh_token,client_credentials");

    mongoTemplate.save(frontofficeServiceClientDetails);
  }

  @ChangeSet(order = "005", id = "insertBackofficeServiceClientDetails", author = "Wanna Go Dev1")
  public void insertBackofficeServiceClientDetails(MongoTemplate mongoTemplate) {
    SecurityClient backofficeServiceClientDetails = new SecurityClient();
    backofficeServiceClientDetails.setClientId("backend-server");
    backofficeServiceClientDetails.setClientSecret(clientPasswordEncoder.encode("1234"));
    backofficeServiceClientDetails.setScopes("backend");
    backofficeServiceClientDetails.setGrantTypes("refresh_token,client_credentials");

    mongoTemplate.save(backofficeServiceClientDetails);
  }

  @ChangeSet(order = "006", id = "insertI18NServiceClientDetails", author = "Wanna Go Dev1")
  public void insertI18NServiceClientDetails(MongoTemplate mongoTemplate) {
    SecurityClient backofficeServiceClientDetails = new SecurityClient();
    backofficeServiceClientDetails.setClientId("i18n-server");
    backofficeServiceClientDetails.setClientSecret(clientPasswordEncoder.encode("1234"));
    backofficeServiceClientDetails.setScopes("i18n");
    backofficeServiceClientDetails.setGrantTypes("refresh_token,client_credentials");

    mongoTemplate.save(backofficeServiceClientDetails);
  }

  @ChangeSet(order = "007", id = "insertAuditServiceClientDetails", author = "Wanna Go Dev1")
  public void insertAuditServiceClientDetails(MongoTemplate mongoTemplate) {
    SecurityClient backofficeServiceClientDetails = new SecurityClient();
    backofficeServiceClientDetails.setClientId("audit-server");
    backofficeServiceClientDetails.setClientSecret(clientPasswordEncoder.encode("1234"));
    backofficeServiceClientDetails.setScopes("audit");
    backofficeServiceClientDetails.setGrantTypes("refresh_token,client_credentials");

    mongoTemplate.save(backofficeServiceClientDetails);
  }

  @ChangeSet(order = "008", id = "insertResourceServiceClientDetails", author = "Wanna Go Dev1")
  public void insertResourceServiceClientDetails(MongoTemplate mongoTemplate) {
    SecurityClient backofficeServiceClientDetails = new SecurityClient();
    backofficeServiceClientDetails.setClientId("resource-server");
    backofficeServiceClientDetails.setClientSecret(clientPasswordEncoder.encode("1234"));
    backofficeServiceClientDetails.setScopes("resource");
    backofficeServiceClientDetails.setGrantTypes("refresh_token,client_credentials");

    mongoTemplate.save(backofficeServiceClientDetails);
  }

  @ChangeSet(order = "009", id = "insertMobileServiceClientDetails", author = "Wanna Go Dev1")
  public void insertMobileServiceClientDetails(MongoTemplate mongoTemplate) {
    SecurityClient frontofficeServiceClientDetails = new SecurityClient();
    frontofficeServiceClientDetails.setClientId("mobile-application");
    frontofficeServiceClientDetails.setClientSecret(clientPasswordEncoder.encode("1234"));
    frontofficeServiceClientDetails.setScopes("mobile");
    frontofficeServiceClientDetails.setGrantTypes("refresh_token,client_credentials");

    mongoTemplate.save(frontofficeServiceClientDetails);
  }

  @ChangeSet(order = "010", id = "insertDynamicClientDetails", author = "Wanna Go Dev1", runAlways = true )
  public void insertDynamicClientDetails( MongoTemplate mongoTemplate) {
    AppProperties appProperties = SpringApplicationContext.getBean(AppProperties.class);
    List<ClientAuth> clientAuths = appProperties.getAuth().getClients();
    clientAuths.forEach( clientAuth -> {
      SecurityClient existing = mongoTemplate.findOne( Query.query(Criteria.where("clientId").is(clientAuth.getClientId())), SecurityClient.class);
      if (existing == null) {
        SecurityClient newRecord = new SecurityClient();
        newRecord.setClientId(clientAuth.getClientId());
        newRecord.setClientSecret(clientPasswordEncoder.encode(clientAuth.getClientSecret()));
        newRecord.setGrantTypes(clientAuth.getGrantTypes());
        newRecord.setScopes(clientAuth.getScope());
        mongoTemplate.save(newRecord);
      }
    });
  }

  @ChangeSet(order = "011", id = "insertNotificationServiceClientDetails", author = "Wanna Go Dev1")
  public void insertNotificationServiceClientDetails(MongoTemplate mongoTemplate) {
    SecurityClient backofficeServiceClientDetails = new SecurityClient();
    backofficeServiceClientDetails.setClientId("notification-server");
    backofficeServiceClientDetails.setClientSecret(clientPasswordEncoder.encode("1234"));
    backofficeServiceClientDetails.setScopes("notification");
    backofficeServiceClientDetails.setGrantTypes("refresh_token,client_credentials");

    mongoTemplate.save(backofficeServiceClientDetails);
  }
}
