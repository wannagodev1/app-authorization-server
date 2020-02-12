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


package org.wannagoframework.authorization.converter;

import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;
import org.wannagoframework.authorization.domain.RememberMeToken;
import org.wannagoframework.authorization.domain.PasswordResetToken;
import org.wannagoframework.authorization.domain.VerificationToken;
import org.wannagoframework.authorization.domain.SecurityRole;
import org.wannagoframework.authorization.domain.SecurityUser;
import org.wannagoframework.commons.utils.OrikaBeanMapper;

/**
 * @author WannaGo Dev1.
 * @version 1.0
 * @since 2019-06-05
 */
@Component
public class SecurityConverter {

  private final OrikaBeanMapper orikaBeanMapper;

  public SecurityConverter(OrikaBeanMapper orikaBeanMapper) {
    this.orikaBeanMapper = orikaBeanMapper;
  }

  @Bean
  public void securityConverters() {
    orikaBeanMapper
        .addMapper(SecurityUser.class, org.wannagoframework.dto.domain.security.SecurityUser.class);
    orikaBeanMapper
        .addMapper(org.wannagoframework.dto.domain.security.SecurityUser.class, SecurityUser.class);

    orikaBeanMapper
        .addMapper(SecurityRole.class, org.wannagoframework.dto.domain.security.SecurityRole.class);
    orikaBeanMapper
        .addMapper(org.wannagoframework.dto.domain.security.SecurityRole.class, SecurityRole.class);

    orikaBeanMapper.addMapper(RememberMeToken.class,
        org.wannagoframework.dto.domain.security.RememberMeToken.class);
    orikaBeanMapper
        .addMapper(org.wannagoframework.dto.domain.security.RememberMeToken.class, RememberMeToken.class);

    orikaBeanMapper.addMapper(VerificationToken.class,
        org.wannagoframework.dto.domain.security.VerificationToken.class);
    orikaBeanMapper
        .addMapper(org.wannagoframework.dto.domain.security.VerificationToken.class, VerificationToken.class);

    orikaBeanMapper.addMapper(PasswordResetToken.class,
        org.wannagoframework.dto.domain.security.PasswordResetToken.class);
    orikaBeanMapper
        .addMapper(org.wannagoframework.dto.domain.security.PasswordResetToken.class, PasswordResetToken.class);
  }
}