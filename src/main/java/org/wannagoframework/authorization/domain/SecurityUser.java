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

import java.time.Instant;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

/**
 * This class represents a Security User used to login and access the application.
 *
 * @author WannaGo Dev1.
 * @version 1.0
 * @since 2019-03-09
 */
@Data
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
@Document
public class SecurityUser extends BaseEntity {

  /**
   * Username
   */
  @NotNull
  @Indexed(unique = true)
  private String username;

  private String email;

  private String mobileNumber;

  private String firstName;

  private String lastName;

  private String nickName;

  private String imageUrl;

  /**
   * Password for login using internal authentication
   */
  @Pattern(regexp = "^(|(?=.*\\d)(?=.*[a-z])(?=.*[A-Z]).{6,})$", message = "need 6 or more chars, mixing digits, lowercase and uppercase letters")
  private String password;

  /**
   * Number of consecutive failed login attempt
   */
  private Integer failedLoginAttempts = 0;

  /**
   * Password last modification date
   */
  private Instant passwordLastModification;

  /**
   * Last successful login date
   */
  private Instant lastSuccessfulLogin;

  /**
   * Does this account has expired ?
   */
  private Boolean isAccountExpired = Boolean.FALSE;

  /**
   * Is this account locked ?
   */
  private Boolean isAccountLocked = Boolean.FALSE;

  /**
   * Is the password expired ?
   */
  private Boolean isCredentialsExpired = Boolean.FALSE;

  private Map<String, String> attributes;

  /**
   * Define the kind of user : Internal, System, External
   */
  @NotNull
  private SecurityUserTypeEnum userType;

  private Locale defaultLocale = Locale.ENGLISH;

  private VerificationToken verificationToken = new VerificationToken();
  private PasswordResetToken passwordResetToken = new PasswordResetToken();
  private RememberMeToken rememberMeToken = new RememberMeToken();
  private Boolean isActivated = Boolean.FALSE;

  @NotNull
  private AuthProviderEnum provider;

  private String providerId;

  /**
   * Security roles for this user
   */
  @DBRef
  private Set<SecurityRole> roles = new HashSet<>();
}
