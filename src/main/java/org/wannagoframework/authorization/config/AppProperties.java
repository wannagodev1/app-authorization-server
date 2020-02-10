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


package org.wannagoframework.authorization.config;

import java.util.ArrayList;
import java.util.List;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app")
public class AppProperties {

  private final Auth auth = new Auth();
  private final ActiveDirectory activeDirectory = new ActiveDirectory();
  private final OAuth2 oauth2 = new OAuth2();
  private final Keystore keystore = new Keystore();
  private final TokenGenerator tokenGenerator = new TokenGenerator();
  private final Hazelcast hazelcast = new Hazelcast();

  public Auth getAuth() {
    return auth;
  }

  public ActiveDirectory getActiveDirectory() {
    return activeDirectory;
  }

  public OAuth2 getOauth2() {
    return oauth2;
  }

  public Keystore getKeystore() {
    return keystore;
  }

  public TokenGenerator getTokenGenerator() {
    return tokenGenerator;
  }

  @Data
  public static class Auth {

    private String tokenSecret;
    private long tokenExpirationMsec;
    private List<ClientAuth> clients = new ArrayList<>();

    @Data
    public static class ClientAuth {
      private String clientId;
      private String clientSecret;
      private String scope;
      private String grantTypes;
    }
  }

  @Data
  public static final class ActiveDirectory {

    private Boolean enabled;
    private String url;
    private String domain;
    private String rootDn;
  }

  @Data
  public static final class OAuth2 {

    private List<String> authorizedRedirectUris = new ArrayList<>();
  }

  @Data
  public static final class Keystore {

    private String password;
  }

  @Data
  public static class TokenGenerator {

    private int verificationTokenExpiry;
    private int passwordTokenExpiry;
    private int rememberMeTokenExpiry;
    private String purgeCronExpression;
  }

  @Data
  public static class Hazelcast {

    private final ManagementCenter managementCenter = new ManagementCenter();
    private int timeToLiveSeconds = 3600;
    private int backupCount = 1;

    @Data
    public static class ManagementCenter {

      private boolean enabled = false;
      private int updateInterval = 3;
      private String url = "";
    }
  }
}
