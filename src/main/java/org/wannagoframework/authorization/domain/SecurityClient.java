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

import java.util.Arrays;
import java.util.Collection;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.springframework.data.mongodb.core.mapping.Document;

/**
 * @author WannaGo Dev1.
 * @version 1.0
 * @since 2019-07-09
 */
@Data
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
@Document
public class SecurityClient extends BaseEntity {

  public String clientId;

  public String clientSecret;

  public String scopes;

  public String grantTypes;

  public Collection<String> getScopes() {
    if (scopes != null) {
      return Arrays.asList(scopes.split(","));
    }
    return null;
  }

  public Collection<String> getGrantTypes() {
    if (grantTypes != null) {
      return Arrays.asList(grantTypes.split(","));
    }
    return null;
  }

}
