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


package org.wannagoframework.authorization.endpoint;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.wannagoframework.authorization.domain.SecurityRole;
import org.wannagoframework.authorization.service.SecurityRoleService;
import org.wannagoframework.commons.endpoint.BaseEndpoint;
import org.wannagoframework.commons.utils.OrikaBeanMapper;
import org.wannagoframework.dto.serviceQuery.ServiceResult;
import org.wannagoframework.dto.serviceQuery.generic.CountAnyMatchingQuery;
import org.wannagoframework.dto.serviceQuery.generic.DeleteByStrIdQuery;
import org.wannagoframework.dto.serviceQuery.generic.FindAnyMatchingQuery;
import org.wannagoframework.dto.serviceQuery.generic.GetByStrIdQuery;
import org.wannagoframework.dto.serviceQuery.generic.SaveQuery;
import org.wannagoframework.dto.serviceQuery.security.securityRole.GetSecurityRoleByNameQuery;

/**
 * @author WannaGo Dev1.
 * @version 1.0
 * @since 2019-06-05
 */
@RestController
@RequestMapping("/securityRole")
public class SecurityRoleServiceEndpoint extends BaseEndpoint {

  private final SecurityRoleService securityRoleService;

  public SecurityRoleServiceEndpoint(
      SecurityRoleService securityRoleService,
      OrikaBeanMapper mapperFacade) {
    super(mapperFacade);
    this.securityRoleService = securityRoleService;
  }

  @PreAuthorize("#oauth2.hasAnyScope('frontend','backend')")
  @PostMapping(value = "/getAllowedLoginRoles")
  public ResponseEntity<ServiceResult> getAllowedLoginRoles() {
    String loggerPrefix = getLoggerPrefix("getAllowedLoginRoles");
    try {
      return handleResult(loggerPrefix, mapperFacade
          .mapAsList(securityRoleService.getAllowedLoginRoles(),
              org.wannagoframework.dto.domain.security.SecurityRole.class));
    } catch (Throwable t) {
      return handleResult(loggerPrefix, t);
    }
  }

  @PreAuthorize("#oauth2.hasAnyScope('frontend','backend')")
  @PostMapping(value = "/getSecurityRoleByName")
  public ResponseEntity<ServiceResult> getSecurityRoleByName(
      @RequestBody GetSecurityRoleByNameQuery query) {
    String loggerPrefix = getLoggerPrefix("getSecurityRoleByName");
    try {
      return handleResult(loggerPrefix, mapperFacade
          .map(securityRoleService.getSecurityRoleByName(query.getName()),
              org.wannagoframework.dto.domain.security.SecurityRole.class, getOrikaContext(query)));
    } catch (Throwable t) {
      return handleResult(loggerPrefix, t);
    }
  }

  @PreAuthorize("#oauth2.hasAnyScope('frontend','backend')")
  @PostMapping(value = "/findAllActive")
  public ResponseEntity<ServiceResult> findAllActive() {
    String loggerPrefix = getLoggerPrefix("findAllActive");
    try {
      return handleResult(loggerPrefix,
          mapperFacade.mapAsList(securityRoleService.findAllActive(),
              org.wannagoframework.dto.domain.security.SecurityRole.class));
    } catch (Throwable t) {
      return handleResult(loggerPrefix, t);
    }
  }

  @PreAuthorize("#oauth2.hasAnyScope('frontend','backend')")
  @PostMapping(value = "/findAnyMatching")
  public ResponseEntity<ServiceResult> findAnyMatching(@RequestBody FindAnyMatchingQuery query) {
    String loggerPrefix = getLoggerPrefix("findAnyMatching");
    try {
      Page<SecurityRole> result = securityRoleService
          .findAnyMatching(query.getFilter(), query.getShowInactive(),
              mapperFacade.map(query.getPageable(),
                  Pageable.class, getOrikaContext(query)));
      return handleResult(loggerPrefix,
          mapperFacade.map(result, org.wannagoframework.dto.utils.Page.class, getOrikaContext(query)));

    } catch (Throwable t) {
      return handleResult(loggerPrefix, t);
    }
  }

  @PreAuthorize("#oauth2.hasAnyScope('frontend','backend')")
  @PostMapping(value = "/countAnyMatching")
  public ResponseEntity<ServiceResult> countAnyMatching(@RequestBody CountAnyMatchingQuery query) {
    String loggerPrefix = getLoggerPrefix("countAnyMatching");
    try {
      return handleResult(loggerPrefix, securityRoleService
          .countAnyMatching(query.getFilter(), query.getShowInactive()));
    } catch (Throwable t) {
      return handleResult(loggerPrefix, t);
    }
  }

  @PreAuthorize("#oauth2.hasAnyScope('frontend','backend')")
  @PostMapping(value = "/getById")
  public ResponseEntity<ServiceResult> getById(@RequestBody GetByStrIdQuery query) {
    String loggerPrefix = getLoggerPrefix("getById");
    try {
      return handleResult(loggerPrefix, mapperFacade.map(securityRoleService
              .load(query.getId()), org.wannagoframework.dto.domain.security.SecurityRole.class,
          getOrikaContext(query)));
    } catch (Throwable t) {
      return handleResult(loggerPrefix, t);
    }
  }

  @PreAuthorize("#oauth2.hasAnyScope('frontend','backend')")
  @PostMapping(value = "/save")
  public ResponseEntity<ServiceResult> save(
      @RequestBody SaveQuery<org.wannagoframework.dto.domain.security.SecurityRole> query) {
    String loggerPrefix = getLoggerPrefix("save");
    try {
      return handleResult(loggerPrefix, mapperFacade.map(securityRoleService
              .save(mapperFacade
                  .map(query.getEntity(),
                      SecurityRole.class, getOrikaContext(query))),
          org.wannagoframework.dto.domain.security.SecurityRole.class, getOrikaContext(query)));
    } catch (Throwable t) {
      return handleResult(loggerPrefix, t);
    }
  }

  @PreAuthorize("#oauth2.hasAnyScope('frontend','backend')")
  @PostMapping(value = "/delete")
  public ResponseEntity<ServiceResult> delete(@RequestBody DeleteByStrIdQuery query) {
    String loggerPrefix = getLoggerPrefix("delete");
    try {
      securityRoleService
          .delete(query.getId());
      return handleResult(loggerPrefix);
    } catch (Throwable t) {
      return handleResult(loggerPrefix, t);
    }
  }
}