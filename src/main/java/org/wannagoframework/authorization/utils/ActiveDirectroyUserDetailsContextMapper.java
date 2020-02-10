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

import java.util.Collection;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;
import org.springframework.stereotype.Component;
import org.wannagoframework.authorization.domain.AuthProviderEnum;
import org.wannagoframework.authorization.domain.SecurityUser;
import org.wannagoframework.authorization.domain.SecurityUserTypeEnum;
import org.wannagoframework.authorization.repository.SecurityUserRepository;
import org.wannagoframework.authorization.service.SecurityUserService;
import org.wannagoframework.commons.utils.OrikaBeanMapper;

/**
 * @author WannaGo Dev1.
 * @version 1.0
 * @since 9/18/19
 */
@Component
public class ActiveDirectroyUserDetailsContextMapper implements UserDetailsContextMapper {

  private final SecurityUserService securityUserService;
  private final SecurityUserRepository securityUserRepository;
  private final OrikaBeanMapper mapperFacade;

  public ActiveDirectroyUserDetailsContextMapper(
      SecurityUserService securityUserService,
      SecurityUserRepository securityUserRepository,
      OrikaBeanMapper mapperFacade) {
    this.securityUserService = securityUserService;
    this.securityUserRepository = securityUserRepository;
    this.mapperFacade = mapperFacade;
  }

  @Override
  public UserDetails mapUserFromContext(final DirContextOperations ctx, final String username,
      final Collection<? extends GrantedAuthority> authorities) {
    String firstName = ctx.getStringAttribute("givenname");
    String userName = ctx.getStringAttribute("samaccountname");
    String lastName = ctx.getStringAttribute("sn");
    String email = ctx.getStringAttribute("mail");

    SecurityUser result = securityUserService.getSecurityUserByUsername(userName);
    if (result == null) {
      SecurityUser securityUser = new SecurityUser();
      securityUser.setUsername(userName);
      securityUser.setEmail(email);
      securityUser.setLastName(lastName);
      securityUser.setFirstName(firstName);
      securityUser.setProvider(AuthProviderEnum.ACTIVE_DIRECTORY);
      securityUser.setUserType(SecurityUserTypeEnum.EXTERNAL);
      securityUser = securityUserRepository.save(securityUser);

      org.wannagoframework.dto.domain.security.SecurityUser securityUserDTO = new org.wannagoframework.dto.domain.security.SecurityUser();
      mapperFacade.map(securityUser, securityUserDTO);

      return securityUserDTO;
    } else {
      org.wannagoframework.dto.domain.security.SecurityUser securityUserDTO = new org.wannagoframework.dto.domain.security.SecurityUser();
      mapperFacade.map(result, securityUserDTO);
      return securityUserDTO;
    }
  }

  @Override
  public void mapUserToContext(UserDetails user, DirContextAdapter ctx) {

  }
}
