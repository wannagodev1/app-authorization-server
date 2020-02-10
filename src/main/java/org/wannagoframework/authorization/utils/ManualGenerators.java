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

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.MacProvider;
import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

/**
 * @author WannaGo Dev1.
 * @version 1.0
 * @since 2019-07-07
 */
public class ManualGenerators {

  public static void main(String[] args) {
    String key = "thisIsAVeryLongKeyToGenerateMySectet";
    String base64Key = DatatypeConverter.printBase64Binary(key.getBytes());
    System.out.println("--> Generated key 1 = " + base64Key);

    SecretKey myKey = MacProvider.generateKey(SignatureAlgorithm.HS512);
    base64Key = DatatypeConverter.printBase64Binary(myKey.getEncoded());
    System.out.println("--> Generated key 2 = " + base64Key);
  }
}
