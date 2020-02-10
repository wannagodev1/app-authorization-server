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


package org.wannagoframework.authorization.domain;

import java.util.HashMap;
import java.util.Map;

public enum AuthProviderEnum {
  LOCAL("local"),
  LOCAL_EMAIL("localEmail"),
  LOCAL_MOBILE_NUMBER("localMobileNumber"),
  ACTIVE_DIRECTORY("activeDirectory"),
  FACEBOOK("facebook"),
  GOOGLE("google"),
  GITHUB("github"),
  TWITTER("twitter"),
  PINTEREST("pinterest"),
  FOURSQUARE("foursquare");

  //Lookup table
  private static final Map<String, AuthProviderEnum> lookup = new HashMap<>();

  //Populate the lookup table on loading time
  static {
    for (AuthProviderEnum env : AuthProviderEnum.values()) {
      lookup.put(env.getName(), env);
    }
  }

  private final String name;

  //****** Reverse Lookup Implementation************//

  AuthProviderEnum(String name) {
    this.name = name;
  }

  //This method can be used for reverse lookup purpose
  public static AuthProviderEnum get(String name) {
    return lookup.get(name);
  }

  public String getName() {
    return name;
  }

}
