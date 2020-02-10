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

import org.apache.commons.lang3.StringUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.wannagoframework.authorization.domain.RememberMeToken;
import org.wannagoframework.authorization.domain.SecurityUser;
import org.wannagoframework.authorization.exception.BadRequestException;
import org.wannagoframework.authorization.service.SecurityUserService;
import org.wannagoframework.commons.endpoint.BaseEndpoint;
import org.wannagoframework.commons.utils.OrikaBeanMapper;
import org.wannagoframework.dto.serviceQuery.ServiceResult;
import org.wannagoframework.dto.serviceQuery.authentification.ClearRememberMeTokenQuery;
import org.wannagoframework.dto.serviceQuery.authentification.CreateRememberMeTokenQuery;
import org.wannagoframework.dto.serviceQuery.authentification.ForgetPasswordQuery;
import org.wannagoframework.dto.serviceQuery.authentification.GetSecurityUserByRememberMeTokenQuery;
import org.wannagoframework.dto.serviceQuery.authentification.LoginQuery;
import org.wannagoframework.dto.serviceQuery.authentification.PasswordResetQuery;
import org.wannagoframework.dto.serviceQuery.authentification.ResetVerificationTokenQuery;
import org.wannagoframework.dto.serviceQuery.authentification.SignUpQuery;
import org.wannagoframework.dto.serviceQuery.authentification.ValidateUserQuery;
import org.wannagoframework.dto.serviceResponse.authentification.AuthResponse;
import org.wannagoframework.dto.serviceResponse.authentification.AuthStatusEnum;

@RestController
@RequestMapping("/auth")
public class AuthEndpoint extends BaseEndpoint {

  private final SecurityUserService securityUserService;

  public AuthEndpoint(SecurityUserService securityUserService, OrikaBeanMapper mapperFacade) {
    super(mapperFacade);
    this.securityUserService = securityUserService;
  }

  @PostMapping("/login")
  public ResponseEntity<ServiceResult> login(
      @RequestBody LoginQuery query) {
    String loggerPrefix = getLoggerPrefix("login");

    try {
      AuthResponse authResponse = securityUserService
          .authenticateUser(query.getUsername(), query.getPassword());
      if (authResponse.getStatus().equals(AuthStatusEnum.SUCCESS)) {
        return handleResult(loggerPrefix, authResponse);
      } else {
        return handleResult(loggerPrefix,
            new ServiceResult<>(false, authResponse.getStatus().toString(), authResponse));
      }
    } catch (Throwable t) {
      return handleResult(loggerPrefix, t);
    }
  }

  @PostMapping("/signup")
  public ResponseEntity<ServiceResult> signup(@RequestBody SignUpQuery query) {
    String loggerPrefix = getLoggerPrefix("registerUser");
    try {
      if (StringUtils.isNotBlank(query.getEmail()) && securityUserService
          .existsByEmail(query.getEmail())) {
        return handleResult(loggerPrefix, new BadRequestException("Email address already in use."));
      }
      if (StringUtils.isNotBlank(query.getMobileNumber()) && securityUserService
          .existsByMobileNumber(query.getMobileNumber())) {
        return handleResult(loggerPrefix, new BadRequestException("Mobile number already in use."));
      }

      SecurityUser securityUser = securityUserService
          .registerUser(query.getEmail(), query.getMobileNumber(),
              query.getPassword(), query.getIso3Language());

      securityUserService.authenticateUser(securityUser.getUsername(), query.getPassword());
      ServiceResult<String> result = new ServiceResult<>();
      result.setData(securityUser.getId());
      return handleResult(loggerPrefix, result);
    } catch (Throwable t) {
      return handleResult(loggerPrefix, t);
    }
  }

  @PostMapping("/resetVerificationToken")
  public ResponseEntity<ServiceResult> resetVerificationToken(
      @RequestBody ResetVerificationTokenQuery query) {
    String loggerPrefix = getLoggerPrefix("resetVerificationToken");
    try {
      securityUserService.resetVerificationToken(query.getSecurityUserId());

      return handleResult(loggerPrefix);
    } catch (Throwable t) {
      return handleResult(loggerPrefix, t);
    }
  }

  @PostMapping("/forgetPassword")
  public ResponseEntity<ServiceResult> forgetPassword(
      @RequestBody ForgetPasswordQuery query) {
    String loggerPrefix = getLoggerPrefix("forgetPassword");
    try {
      securityUserService.forgetPassword(query.getUsername());

      return handleResult(loggerPrefix);
    } catch (Throwable t) {
      return handleResult(loggerPrefix, t);
    }
  }

  @PostMapping("/validateUser")
  public ResponseEntity<ServiceResult> validateUser(
      @RequestBody ValidateUserQuery query) {
    String loggerPrefix = getLoggerPrefix("validateUser");
    try {
      String token = securityUserService.validateVerificationToken(query.getLastName(), query
              .getFirstName(), query.getEmail(), query.getNickName(), query.getSecurityUserId(),
          query.getVerificationToken());
      ServiceResult<String> result = new ServiceResult<>();
      result.setData(token);
      return handleResult(loggerPrefix, result);
    } catch (Throwable t) {
      return handleResult(loggerPrefix, t);
    }
  }

  @PostMapping("/createRememberMeToken")
  public ResponseEntity<ServiceResult> createRememberMeToken(
      @RequestBody CreateRememberMeTokenQuery query) {
    String loggerPrefix = getLoggerPrefix("createRememberMeToken");
    try {
      RememberMeToken rememberMeToken = securityUserService.createRememberMeTokenForUser(
          query.getSecurityUserId());

      return handleResult(loggerPrefix,
          mapperFacade.map(rememberMeToken, org.wannagoframework.dto.domain.security.RememberMeToken.class,
              getOrikaContext(query)));
    } catch (Throwable t) {
      return handleResult(loggerPrefix, t);
    }
  }

  @PostMapping("/passwordReset")
  public ResponseEntity<ServiceResult> passwordReset(
      @RequestBody PasswordResetQuery query) {
    String loggerPrefix = getLoggerPrefix("passwordReset");
    try {
      securityUserService.validatePasswordToken(query.getUsername(),
          query.getPasswordResetToken(), query.getNewPassword());

      return handleResult(loggerPrefix);
    } catch (Throwable t) {
      return handleResult(loggerPrefix, t);
    }
  }

  @PostMapping("/clearRememberMeToken")
  public ResponseEntity<ServiceResult> clearRememberMeToken(
      @RequestBody ClearRememberMeTokenQuery query) {
    String loggerPrefix = getLoggerPrefix("clearRememberMeToken");
    try {
      securityUserService.clearRememeberMeToken(query.getRememberMeToken());

      return handleResult(loggerPrefix);
    } catch (Throwable t) {
      return handleResult(loggerPrefix, t);
    }
  }

  @PostMapping(value = "/getSecurityUserIdByRememberMeToken")
  public ResponseEntity<ServiceResult> getSecurityUserByRememberMeToken(
      @RequestBody GetSecurityUserByRememberMeTokenQuery query) {
    String loggerPrefix = getLoggerPrefix("getSecurityUserByRememberMeToken");
    try {
      SecurityUser securityUser = securityUserService.getSecurityUserByRememberMeToken(
          query.getRememberMeToken());
      if (securityUser == null) {
        return handleResult(loggerPrefix, "Not Found");
      } else {
        return handleResult(loggerPrefix,
            mapperFacade
                .map(securityUser, org.wannagoframework.dto.domain.security.SecurityUser.class,
                    getOrikaContext(query)));
      }
    } catch (Throwable t) {
      return handleResult(loggerPrefix, t);
    }
  }
}


