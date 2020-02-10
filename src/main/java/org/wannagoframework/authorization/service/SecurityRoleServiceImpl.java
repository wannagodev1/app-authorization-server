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


package org.wannagoframework.authorization.service;

import java.util.List;
import java.util.Set;
import org.apache.commons.lang3.StringUtils;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.wannagoframework.authorization.domain.SecurityRole;
import org.wannagoframework.authorization.repository.SecurityRoleRepository;

/**
 * @author WannaGo Dev1.
 * @version 1.0
 * @since 2019-04-16
 */

@Service
@Transactional(readOnly = true)
public class SecurityRoleServiceImpl implements SecurityRoleService {

  private final SecurityRoleRepository securityRoleRepository;


  public SecurityRoleServiceImpl(
      SecurityRoleRepository securityRoleRepository) {
    this.securityRoleRepository = securityRoleRepository;
  }

  @Override
  public Page<SecurityRole> findAnyMatching(String filter, Boolean showInactive,
      Pageable pageable) {
    if (StringUtils.isNotBlank(filter) && showInactive != null) {
      return securityRoleRepository.findByNameLikeAndIsActive(filter, showInactive, pageable);
    } else if (StringUtils.isNotBlank(filter)) {
      return securityRoleRepository.findByNameLike(filter, pageable);
    } else if (showInactive != null) {
      return securityRoleRepository.findByIsActive(showInactive, pageable);
    } else {
      return securityRoleRepository.findAll(pageable);
    }
  }

  @Override
  public long countAnyMatching(String filter, Boolean showInactive) {
    if (StringUtils.isNotBlank(filter) && showInactive != null) {
      return securityRoleRepository.countByNameLikeAndIsActive(filter, showInactive);
    } else if (StringUtils.isNotBlank(filter)) {
      return securityRoleRepository.countByNameLike(filter);
    } else if (showInactive != null) {
      return securityRoleRepository.countByIsActive(showInactive);
    } else {
      return securityRoleRepository.count();
    }
  }

  @Override
  public SecurityRole getRoleById(String id) {
    return securityRoleRepository.findById(id).get();
  }

  @Override
  public Set<SecurityRole> getAllowedLoginRoles() {
    return securityRoleRepository.findByCanLogin(true);
  }

  @Override
  public SecurityRole getSecurityRoleByName(String name) {
    return securityRoleRepository.getByNameIgnoreCase(name);
  }

  @Override
  public SecurityRoleRepository getRepository() {
    return securityRoleRepository;
  }

  @Override
  public List<SecurityRole> findAllActive() {
    return securityRoleRepository.findByIsActiveOrderByNameAsc(true);
  }
}
