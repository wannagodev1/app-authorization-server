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


package org.wannagoframework.authorization.utils;

import org.apache.commons.codec.binary.Base64;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.util.SerializationUtils;

public class SerializableObjectConverter {

  private SerializableObjectConverter() {
    throw new IllegalStateException();
  }

  public static String serialize(OAuth2Authentication object) {
    byte[] bytes = SerializationUtils.serialize(object);
    return Base64.encodeBase64String(bytes);
  }

  public static OAuth2Authentication deserialize(String encodedObject) {
    byte[] bytes = Base64.decodeBase64(encodedObject);
    return (OAuth2Authentication) SerializationUtils.deserialize(bytes);
  }

}