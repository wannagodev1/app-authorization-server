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

import java.util.Date;
import java.util.Optional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.wannagoframework.authorization.domain.PasswordResetToken;
import org.wannagoframework.authorization.domain.RememberMeToken;
import org.wannagoframework.authorization.domain.SecurityUser;
import org.wannagoframework.authorization.domain.VerificationToken;
import org.wannagoframework.authorization.exception.PasswordResetNotSupportedException;
import org.wannagoframework.authorization.exception.UsernameNotFoundException;
import org.wannagoframework.dto.serviceResponse.authentification.AuthResponse;

/**
 * @author WannaGo Dev1.
 * @version 1.0
 * @since 2019-04-16
 */
public interface SecurityUserService extends BaseCrudService<SecurityUser>, UserDetailsService {

  SecurityUser getSecurityUserByUsername(String username);

  Page<SecurityUser> findAnyMatching(String filter, Boolean showInactive, Pageable pageable);

  long countAnyMatching(String filter, Boolean showInactive);

  Optional<SecurityUser> getById(String id);

  SecurityUser registerUser(String email, String mobileNumber, String password,
      String iso3Language);

  boolean existsByEmail(String email);

  boolean existsByMobileNumber(String mobileNumber);

  AuthResponse authenticateUser(String username, String password);

  RememberMeToken createRememberMeTokenForUser(String securityUserId);

  RememberMeToken createRememberMeTokenForUser(SecurityUser securityUser);

  void clearRememeberMeToken(String rememberMeToken);

  String createVerificationTokenForUser(SecurityUser securityUser);

  VerificationToken getVerificationToken(String verificationToken);

  String createPasswordResetTokenForUser(SecurityUser securityUser);

  void forgetPassword(String username)
      throws UsernameNotFoundException, PasswordResetNotSupportedException;

  PasswordResetToken getPasswordResetToken(String token);

  void changeUserPassword(SecurityUser securityUser, String newPassword);

  boolean checkIfValidOldPassword(SecurityUser securityUser, String oldPassword);

  void deleteVerificationTokenByExpiryDateLessThan(Date now);

  void deletePasswordResetTokenByExpiryDateLessThan(Date now);

  void resetVerificationToken(String securityUserId);

  String validateVerificationToken(String lastName, String firstName, String email, String nickName, String securityUserId,
      String verificationToken);

  String validatePasswordToken(String username, String passwordResetToken, String newPassword);


  SecurityUser getSecurityUserByRememberMeToken(String rememberMeToken);

  void deleteRemeberByTokenByExpiryDateLessThan(Date now);
}
