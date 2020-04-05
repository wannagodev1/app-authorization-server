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

import java.security.Principal;
import ma.glasnost.orika.MappingContext;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.wannagoframework.authorization.domain.SecurityUser;
import org.wannagoframework.authorization.exception.ResourceNotFoundException;
import org.wannagoframework.authorization.security.CurrentUser;
import org.wannagoframework.authorization.service.SecurityUserService;
import org.wannagoframework.commons.endpoint.BaseEndpoint;
import org.wannagoframework.commons.utils.OrikaBeanMapper;
import org.wannagoframework.dto.serviceQuery.ServiceResult;
import org.wannagoframework.dto.serviceQuery.generic.CountAnyMatchingQuery;
import org.wannagoframework.dto.serviceQuery.generic.DeleteByStrIdQuery;
import org.wannagoframework.dto.serviceQuery.generic.FindAnyMatchingQuery;
import org.wannagoframework.dto.serviceQuery.generic.GetByStrIdQuery;
import org.wannagoframework.dto.serviceQuery.generic.SaveQuery;
import org.wannagoframework.dto.serviceQuery.security.securityUser.GetSecurityUserByUsernameQuery;

/**
 * @author WannaGo Dev1.
 * @version 1.0
 * @since 2019-06-05
 */
@RestController
@RequestMapping("/securityUser")
public class SecurityUserServiceEndpoint extends BaseEndpoint {

  private final SecurityUserService securityUserService;

  public SecurityUserServiceEndpoint(
      SecurityUserService securityUserService,
      OrikaBeanMapper mapperFacade) {
    super(mapperFacade);
    this.securityUserService = securityUserService;
  }

  @GetMapping("/me")
  public SecurityUser getUser(
      @CurrentUser org.wannagoframework.dto.domain.security.SecurityUser principal) {
    return securityUserService.getById(principal.getId())
        .orElseThrow(() -> new ResourceNotFoundException("User", "id", principal.getId()));
  }

  @GetMapping("/current")
  public Principal getUser(Principal principal) {
    return principal;
  }

  //@PreAuthorize("#oauth2.hasAnyScope('frontend','backend')")
  @PostMapping(value = "/getSecurityUserByUsername")
  public ResponseEntity<ServiceResult> getSecurityUserByUsername(
      @RequestBody GetSecurityUserByUsernameQuery query) {
    String loggerPrefix = getLoggerPrefix("getSecurityUserByUsername");
    try {
      SecurityUser result = securityUserService
          .getSecurityUserByUsername(query.getUsername());
      return handleResult(loggerPrefix,
          mapperFacade.map(result, org.wannagoframework.dto.domain.security.SecurityUser.class,
              getOrikaContext(query)));
    } catch (Throwable t) {
      return handleResult(loggerPrefix, t);
    }
  }

  @PreAuthorize("#oauth2.hasAnyScope('frontend','backend')")
  @PostMapping(value = "/findAnyMatching")
  public ResponseEntity<ServiceResult> findAnyMatching(@RequestBody FindAnyMatchingQuery query) {
    String loggerPrefix = getLoggerPrefix("findAnyMatching");
    MappingContext context = new MappingContext.Factory().getContext();
    context.setProperty("iso3Language", query.get_iso3Language());
    try {
      Page<SecurityUser> result = securityUserService
          .findAnyMatching(query.getFilter(), query.getShowInactive(),
              mapperFacade.map(query.getPageable(),
                  Pageable.class));
      return handleResult(loggerPrefix,
          mapperFacade.map(result, org.wannagoframework.dto.utils.Page.class, context));
    } catch (Throwable t) {
      return handleResult(loggerPrefix, t);
    }
  }

  @PreAuthorize("#oauth2.hasAnyScope('frontend','backend')")
  @PostMapping(value = "/countAnyMatching")
  public ResponseEntity<ServiceResult> countAnyMatching(@RequestBody CountAnyMatchingQuery query) {
    String loggerPrefix = getLoggerPrefix("countAnyMatching");
    try {
      return handleResult(loggerPrefix, securityUserService
          .countAnyMatching(query.getFilter(), query.getShowInactive()));
    } catch (Throwable t) {
      return handleResult(loggerPrefix, t);
    }
  }

  @PostMapping(value = "/getById")
  public ResponseEntity<ServiceResult> getById(@RequestBody GetByStrIdQuery query) {
    String loggerPrefix = getLoggerPrefix("getById");
    try {
      return handleResult(loggerPrefix, mapperFacade.map(securityUserService
              .load(query.getId()), org.wannagoframework.dto.domain.security.SecurityUser.class,
          getOrikaContext(query)));
    } catch (Throwable t) {
      return handleResult(loggerPrefix, t);
    }
  }

  @PreAuthorize("#oauth2.hasAnyScope('frontend','backend')")
  @PostMapping(value = "/save")
  public ResponseEntity<ServiceResult> save(
      @RequestBody SaveQuery<org.wannagoframework.dto.domain.security.SecurityUser> query) {
    String loggerPrefix = getLoggerPrefix("save");
    try {
      return handleResult(loggerPrefix, mapperFacade.map(securityUserService
              .save(mapperFacade
                  .map(query.getEntity(), SecurityUser.class, getOrikaContext(query))),
          org.wannagoframework.dto.domain.security.SecurityUser.class, getOrikaContext(query)));
    } catch (Throwable t) {
      return handleResult(loggerPrefix, t);
    }
  }

  @PreAuthorize("#oauth2.hasAnyScope('frontend','backend')")
  @PostMapping(value = "/delete")
  public ResponseEntity<ServiceResult> delete(@RequestBody DeleteByStrIdQuery query) {
    String loggerPrefix = getLoggerPrefix("delete");
    try {
      securityUserService
          .delete(query.getId());
      return handleResult(loggerPrefix);
    } catch (Throwable t) {
      return handleResult(loggerPrefix, t);
    }
  }
}
