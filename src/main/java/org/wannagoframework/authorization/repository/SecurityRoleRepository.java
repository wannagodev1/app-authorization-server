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


package org.wannagoframework.authorization.repository;

import java.util.List;
import java.util.Set;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;
import org.wannagoframework.authorization.domain.SecurityRole;

@Repository
public interface SecurityRoleRepository extends MongoRepository<SecurityRole, String> {

  Page<SecurityRole> findByNameLikeAndIsActive(String filter, Boolean showInactive,
      Pageable pageable);

  Page<SecurityRole> findByNameLike(String filter, Pageable pageable);

  Page<SecurityRole> findByIsActive(Boolean showInactive, Pageable pageable);

  long countByNameLikeAndIsActive(String filter, Boolean showInactive);

  long countByNameLike(String filter);

  long countByIsActive(Boolean showInactive);

  Set<SecurityRole> findByCanLogin(boolean canLogin);

  SecurityRole getByNameIgnoreCase(String name);

  List<SecurityRole> findByIsActiveOrderByNameAsc(boolean b);
}
