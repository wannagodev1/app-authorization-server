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

import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.UUID;
import org.apache.commons.lang3.StringUtils;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapAuthenticationProvider;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.wannagoframework.authorization.client.AuthorizationEmailSenderQueue;
import org.wannagoframework.authorization.config.AppProperties;
import org.wannagoframework.authorization.domain.AuthProviderEnum;
import org.wannagoframework.authorization.domain.MailActionEnum;
import org.wannagoframework.authorization.domain.MailTemplate;
import org.wannagoframework.authorization.domain.PasswordResetToken;
import org.wannagoframework.authorization.domain.RememberMeToken;
import org.wannagoframework.authorization.domain.SecurityUser;
import org.wannagoframework.authorization.domain.SecurityUserTypeEnum;
import org.wannagoframework.authorization.domain.SmsActionEnum;
import org.wannagoframework.authorization.domain.SmsTemplate;
import org.wannagoframework.authorization.domain.VerificationToken;
import org.wannagoframework.authorization.exception.PasswordResetNotSupportedException;
import org.wannagoframework.authorization.exception.ResourceNotFoundException;
import org.wannagoframework.authorization.exception.UserFriendlyDataException;
import org.wannagoframework.authorization.exception.UsernameNotFoundException;
import org.wannagoframework.authorization.repository.SecurityRoleRepository;
import org.wannagoframework.authorization.repository.SecurityUserRepository;
import org.wannagoframework.authorization.security.TokenProvider;
import org.wannagoframework.authorization.utils.ActiveDirectroyUserDetailsContextMapper;
import org.wannagoframework.commons.utils.FreeMakerProcessor;
import org.wannagoframework.commons.SecurityConst;
import org.wannagoframework.commons.security.SecurityUtils;
import org.wannagoframework.commons.utils.HasLogger;
import org.wannagoframework.commons.utils.OrikaBeanMapper;
import org.wannagoframework.dto.domain.notification.Mail;
import org.wannagoframework.dto.domain.notification.MailStatusEnum;
import org.wannagoframework.dto.domain.notification.Sms;
import org.wannagoframework.dto.domain.notification.SmsStatusEnum;
import org.wannagoframework.dto.serviceResponse.authentification.AuthResponse;
import org.wannagoframework.dto.serviceResponse.authentification.AuthStatusEnum;
import org.wannagoframework.dto.utils.AppContextThread;

/**
 * @author WannaGo Dev1.
 * @version 1.0
 * @since 2019-04-16
 */
@Service
@Transactional(readOnly = true)
public class SecurityUserServiceImpl implements SecurityUserService, HasLogger {

  public static final String MODIFY_LOCKED_USER_NOT_PERMITTED = "Security User has been locked and cannot be modified or deleted";
  public static final String DELETING_SELF_NOT_PERMITTED = "You cannot delete your own account";
  public static final String USER_EXISTS = "User not available";

  private final SecurityUserRepository securityUserRepository;
  private final SecurityRoleRepository securityRoleRepository;
  private final MailTemplateService mailTemplateService;
  private final SmsTemplateService smsTemplateService;
  private final AuthenticationManager authenticationManager;
  private final TokenProvider tokenProvider;
  private final AuthorizationEmailSenderQueue authorizationEmailSenderQueue;
  private final PasswordEncoder passwordEncoder;
  private final OrikaBeanMapper mapperFacade;
  private final AppProperties appProperties;
  private final FreeMakerProcessor freeMakerProcessor;
  private ActiveDirectoryLdapAuthenticationProvider activeDirectoryLdapAuthenticationProvider;
  private Random randon = new Random();

  public SecurityUserServiceImpl(
      SecurityUserRepository securityUserRepository,
      SecurityRoleRepository securityRoleRepository,
      MailTemplateService mailTemplateService,
      SmsTemplateService smsTemplateService,
      AuthenticationManager authenticationManager,
      TokenProvider tokenProvider,
      AuthorizationEmailSenderQueue authorizationEmailSenderQueue,
      PasswordEncoder passwordEncoder, OrikaBeanMapper mapperFacade,
      AppProperties appProperties,
      FreeMakerProcessor freeMakerProcessor) {
    this.securityUserRepository = securityUserRepository;
    this.securityRoleRepository = securityRoleRepository;
    this.mailTemplateService = mailTemplateService;
    this.smsTemplateService = smsTemplateService;
    this.authenticationManager = authenticationManager;
    this.tokenProvider = tokenProvider;
    this.authorizationEmailSenderQueue = authorizationEmailSenderQueue;
    this.passwordEncoder = passwordEncoder;
    this.mapperFacade = mapperFacade;
    this.appProperties = appProperties;
    this.freeMakerProcessor = freeMakerProcessor;
    if (appProperties.getActiveDirectory().getEnabled()) {
      this.activeDirectoryLdapAuthenticationProvider = new ActiveDirectoryLdapAuthenticationProvider(
          null, appProperties.getActiveDirectory().getUrl(),
          appProperties.getActiveDirectory().getRootDn());
      this.activeDirectoryLdapAuthenticationProvider.setUserDetailsContextMapper(
          new ActiveDirectroyUserDetailsContextMapper(this, securityUserRepository, mapperFacade));
    }
  }

  @Override
  public SecurityUser getSecurityUserByUsername(String username) {
    return securityUserRepository.getByUsernameIgnoreCase(username);
  }

  @Override
  public Page<SecurityUser> findAnyMatching(String filter, Boolean showInactive,
      Pageable pageable) {
    if (StringUtils.isNotBlank(filter) && showInactive != null) {
      return securityUserRepository.findByUsernameLikeAndIsActive(filter, showInactive, pageable);
    } else if (StringUtils.isNotBlank(filter)) {
      return securityUserRepository.findByUsernameLike(filter, pageable);
    } else if (showInactive != null) {
      return securityUserRepository.findByIsActive(showInactive, pageable);
    } else {
      return securityUserRepository.findAll(pageable);
    }
  }

  @Override
  public long countAnyMatching(String filter, Boolean showInactive) {
    if (StringUtils.isNotBlank(filter) && showInactive != null) {
      return securityUserRepository.countByUsernameLikeAndIsActive(filter, showInactive);
    } else if (StringUtils.isNotBlank(filter)) {
      return securityUserRepository.countByUsername(filter);
    } else if (showInactive != null) {
      return securityUserRepository.countByIsActive(showInactive);
    } else {
      return securityUserRepository.count();
    }
  }

  @Override
  public SecurityUserRepository getRepository() {
    return securityUserRepository;
  }

  public Page<SecurityUser> find(Pageable pageable) {
    return getRepository().findAll(pageable);
  }

  @Override
  @Transactional
  public SecurityUser save(SecurityUser entity) {
    throwIfUserLocked(entity);

    SecurityUser existingSecurityUser = null;
    if (entity.getId() == null) {
      throwIfUsernameExists(entity.getUsername());
    } else {
      existingSecurityUser = securityUserRepository.findById(entity.getId()).get();
    }

    if (existingSecurityUser == null || !existingSecurityUser.getPassword()
        .equals(entity.getPassword())) {
      entity.setPassword(passwordEncoder.encode(entity.getPassword()));
    }

    return securityUserRepository.save(entity);
  }

  @Override
  @Transactional
  public void delete(SecurityUser userToDelete) {
    throwIfDeletingSelf(userToDelete);
    throwIfUserLocked(userToDelete);

    SecurityUserService.super.delete(userToDelete);
  }

  @Override
  public Optional<SecurityUser> getById(String id) {
    return securityUserRepository.findById(id);
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    SecurityUser user = securityUserRepository.findByUsername(username)
        .orElseThrow(() -> new UsernameNotFoundException("Username " + username + " not found"));

    org.wannagoframework.dto.domain.security.SecurityUser securityUserDTO = new org.wannagoframework.dto.domain.security.SecurityUser();
    mapperFacade.map(user, securityUserDTO);
    return securityUserDTO;
  }

  @Override
  @Transactional
  public SecurityUser registerUser(String email, String mobileNumber, String password,
      String iso3Language) {
    boolean isEmailUsername;
    SecurityUser user = new SecurityUser();
    if (StringUtils.isNotBlank(email)) {
      user.setUsername(email);
      isEmailUsername = true;
    } else {
      user.setUsername(mobileNumber);
      isEmailUsername = false;
    }
    user.setMobileNumber(mobileNumber);
    user.setEmail(email);
    user.setPassword(password);
    user.setProvider(
        isEmailUsername ? AuthProviderEnum.LOCAL_EMAIL : AuthProviderEnum.LOCAL_MOBILE_NUMBER);
    user.setUserType(SecurityUserTypeEnum.EXTERNAL);
    user.setPassword(passwordEncoder.encode(user.getPassword()));
    user.getRoles().add(securityRoleRepository.getByNameIgnoreCase("EXTERNAL"));
    user.setDefaultLocale(new Locale(iso3Language));
    SecurityUser result = securityUserRepository.save(user);

    String token = createVerificationTokenForUser(result);

    if (isEmailUsername) {
      final Optional<MailTemplate> byMailAction = mailTemplateService.findByMailAction(
          MailActionEnum.EMAIL_VERIFICATION.name(), iso3Language);
      byMailAction.ifPresent(mailTemplate -> {
        final Mail mail = new Mail();

        final Map<String, String> attributes = new HashMap<>();
        attributes.put("verificationCode", token);
        mail.setMailStatus(MailStatusEnum.NOT_SENT);
        // initialize saved mail data
        mail.setFrom(mailTemplate.getFrom());
        mail.setTo(email);
        if (StringUtils.isNotBlank(mailTemplate.getCopyTo())) {
          mail.setCopyTo(mailTemplate.getCopyTo());
        }

        String html = freeMakerProcessor.process(mailTemplate.getBody(), attributes);
        mail.setBody(html);
        String subject = freeMakerProcessor.process(mailTemplate.getSubject(), attributes);
        mail.setSubject(subject);
        authorizationEmailSenderQueue.sendMail(mail);
      });
    } else {
      final Optional<SmsTemplate> bySmsAction = smsTemplateService
          .findBySmsAction(SmsActionEnum.SMS_VERIFICATION.name(), iso3Language);
      bySmsAction.ifPresent(smsTemplate -> {
        Sms sms = new Sms();
        sms.setSmsStatus(SmsStatusEnum.NOT_SENT);
        Map<String, String> attributes = new HashMap<>();
        attributes.put("verificationCode", token);

        String html = freeMakerProcessor.process(smsTemplate.getBody(), attributes);

        // initialize saved sms data
        sms.setPhoneNumber(mobileNumber);
        sms.setBody(html);
        authorizationEmailSenderQueue.sendSms(sms);
      });
    }
    return result;
  }

  @Override
  @Transactional
  public void forgetPassword(String username)
      throws UsernameNotFoundException, PasswordResetNotSupportedException {
    SecurityUser securityUser = securityUserRepository.getByUsernameIgnoreCase(username);
    if (securityUser == null) {
      throw new UsernameNotFoundException(username);
    }

    if (securityUser.getProvider().equals(AuthProviderEnum.LOCAL_EMAIL)) {
      final Optional<MailTemplate> byMailAction = mailTemplateService
          .findByMailAction(MailActionEnum.EMAIL_FORGET_PASSWORD.name(), securityUser.getDefaultLocale().getISO3Language());
      byMailAction.ifPresent(mailTemplate -> {
        final Mail mail = new Mail();

        final Map<String, String> attributes = new HashMap<>();
        attributes.put("resetCode", createPasswordResetTokenForUser(securityUser));
        mail.setMailStatus(MailStatusEnum.NOT_SENT);
        // initialize saved mail data
        mail.setFrom(mailTemplate.getFrom());
        mail.setTo(securityUser.getEmail());
        if (StringUtils.isNotBlank(mailTemplate.getCopyTo())) {
          mail.setCopyTo(mailTemplate.getCopyTo());
        }

        String html = freeMakerProcessor.process(mailTemplate.getBody(), attributes);
        mail.setBody(html);
        String subject = freeMakerProcessor.process(mailTemplate.getSubject(), attributes);
        mail.setSubject(subject);
        authorizationEmailSenderQueue.sendMail(mail);
      });
    } else if (securityUser.getProvider().equals(AuthProviderEnum.LOCAL_MOBILE_NUMBER)) {
      final Optional<SmsTemplate> bySmsAction = smsTemplateService
          .findBySmsAction(SmsActionEnum.SMS_FORGET_PASSWORD.name(), securityUser.getDefaultLocale().getISO3Language());
      bySmsAction.ifPresent(smsTemplate -> {
        Sms sms = new Sms();
        sms.setSmsStatus(SmsStatusEnum.NOT_SENT);
        Map<String, String> attributes = new HashMap<>();
        attributes.put("resetCode", createPasswordResetTokenForUser(securityUser));

        String html = freeMakerProcessor.process(smsTemplate.getBody(), attributes);

        // initialize saved sms data
        sms.setPhoneNumber(securityUser.getMobileNumber());
        sms.setBody(html);
        authorizationEmailSenderQueue.sendSms(sms);
      });
    } else {
      throw new PasswordResetNotSupportedException(securityUser.getProvider().toString());
    }
  }

  @Override
  @Transactional
  public void resetVerificationToken(String securityUserId) {
    Optional<SecurityUser> _securityUser = securityUserRepository.findById(securityUserId);
    if (_securityUser.isPresent()) {
      SecurityUser securityUser = _securityUser.get();
      String token = createVerificationTokenForUser(_securityUser.get());

      if (securityUser.getProvider().equals(AuthProviderEnum.LOCAL_EMAIL)) {

        final String iso3Language = securityUser.getDefaultLocale() == null ? Locale.ENGLISH.getLanguage() : securityUser.getDefaultLocale().getLanguage();
        final Optional<MailTemplate> byMailAction = mailTemplateService.findByMailAction(
            MailActionEnum.EMAIL_VERIFICATION.name(), iso3Language);
        byMailAction.ifPresent(mailTemplate -> {
          final Mail mail = new Mail();

          final Map<String, String> attributes = new HashMap<>();
          attributes.put("verificationCode", token);
          mail.setMailStatus(MailStatusEnum.NOT_SENT);
          // initialize saved mail data
          mail.setFrom(mailTemplate.getFrom());
          mail.setTo(securityUser.getEmail());
          if (StringUtils.isNotBlank(mailTemplate.getCopyTo())) {
            mail.setCopyTo(mailTemplate.getCopyTo());
          }

          String html = freeMakerProcessor.process(mailTemplate.getBody(), attributes);
          mail.setBody(html);
          String subject = freeMakerProcessor.process(mailTemplate.getSubject(), attributes);
          mail.setSubject(subject);
          authorizationEmailSenderQueue.sendMail(mail);
        });

      } else {
        final String iso3Language = securityUser.getDefaultLocale() == null ? Locale.ENGLISH.getLanguage()
            : securityUser.getDefaultLocale().getLanguage();
        final Optional<SmsTemplate> bySmsAction = smsTemplateService
            .findBySmsAction(SmsActionEnum.SMS_VERIFICATION.name(), iso3Language);
        bySmsAction.ifPresent(smsTemplate -> {
          Sms sms = new Sms();
          sms.setSmsStatus(SmsStatusEnum.NOT_SENT);
          Map<String, String> attributes = new HashMap<>();
          attributes.put("verificationCode", token);

          String body = freeMakerProcessor.process(smsTemplate.getBody(), attributes);

          // initialize saved sms data
          sms.setPhoneNumber(securityUser.getMobileNumber());
          sms.setBody(body);
          authorizationEmailSenderQueue.sendSms(sms);
        });

      }
    }
  }

  @Override
  public boolean existsByEmail(String email) {
    return securityUserRepository.existsByEmail(email);
  }

  @Override
  public boolean existsByMobileNumber(String mobileNumber) {
    return securityUserRepository.existsByMobileNumber(mobileNumber);
  }

  @Override
  @Transactional
  public AuthResponse authenticateUser(String username, String password) {
    String loggerPrefix =  getLoggerPrefix("authenticateUser");
    Authentication authentication = null;
    AuthResponse authResponse = new AuthResponse();

    Optional<SecurityUser> _securityUser = securityUserRepository.findByUsername(username);
    if  ( ! _securityUser.isPresent() ) {
      logger().warn(loggerPrefix+"Username not found");
      authResponse.setStatus(AuthStatusEnum.BAD_CREDENTIALS);
    } else {
      UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username,
          password);
      if (appProperties.getActiveDirectory().getEnabled() && StringUtils.isNotBlank(_securityUser.get().getEmail())) {
        try {
          authentication = activeDirectoryLdapAuthenticationProvider.authenticate(new UsernamePasswordAuthenticationToken(_securityUser.get().getEmail(), password));
        } catch (BadCredentialsException e) {
        }
      }
      if (authentication == null || !authentication.isAuthenticated()) {
        try {
          authentication = authenticationManager.authenticate(token);
        } catch (BadCredentialsException  e) {
          authResponse.setStatus(AuthStatusEnum.BAD_CREDENTIALS);
          _securityUser.ifPresent(securityUser -> {
          securityUser.setFailedLoginAttempts(securityUser.getFailedLoginAttempts() + 1);
          if (securityUser.getFailedLoginAttempts() > 2) {
            securityUser.setIsAccountLocked(true);
            authResponse.setStatus(AuthStatusEnum.LOCKED);
          }
          securityUserRepository.save(securityUser);
        });
        } catch ( LockedException e ) {
          authResponse.setStatus(AuthStatusEnum.LOCKED);
        }
      } else {
        _securityUser.ifPresent(securityUser -> {
          securityUser.setFailedLoginAttempts(0);
          securityUserRepository.save(securityUser);
        });
      }

      if (authResponse.getStatus() == null) {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        authResponse.setStatus(AuthStatusEnum.SUCCESS);
        authResponse.setAccessToken(tokenProvider.createToken(authentication));
        org.wannagoframework.dto.domain.security.SecurityUser securityUser = (org.wannagoframework.dto.domain.security.SecurityUser) authentication
            .getPrincipal();
        if (!securityUser.getIsActivated()) {
          authResponse.setStatus(AuthStatusEnum.NOT_ACTIVATED);
        }
      }
    }
    return authResponse;
  }

  @Override
  @Transactional
  public RememberMeToken createRememberMeTokenForUser(String securityUserId) {
    Optional<SecurityUser> _securityUser = securityUserRepository.findById(securityUserId);
    if (_securityUser.isPresent()) {
      return createRememberMeTokenForUser(_securityUser.get());
    } else {
      return null;
    }
  }

  @Override
  @Transactional
  public String createVerificationTokenForUser(SecurityUser securityUser) {
    String newToken = getNewVerificationToken();
    securityUser.setVerificationToken(new VerificationToken(newToken,
        calculateExpiryDate(appProperties.getTokenGenerator().getVerificationTokenExpiry())));
    securityUserRepository.save(securityUser);

    return newToken;
  }

  @Override
  public VerificationToken getVerificationToken(String verificationToken) {
    SecurityUser securityUser = securityUserRepository.findByVerificationToken(verificationToken);
    if (securityUser != null) {
      return securityUser.getVerificationToken();
    } else {
      return null;
    }
  }

  @Override
  @Transactional
  public String createPasswordResetTokenForUser(SecurityUser securityUser) {
    String newToken = getNewVerificationToken();
    securityUser.setPasswordResetToken(new PasswordResetToken(newToken,
        calculateExpiryDate(appProperties.getTokenGenerator().getPasswordTokenExpiry())));
    securityUserRepository.save(securityUser);

    return newToken;
  }

  @Override
  @Transactional
  public RememberMeToken createRememberMeTokenForUser(SecurityUser securityUser) {
    RememberMeToken rememberMeToken = new RememberMeToken(getNewRememberMeToken(),
        calculateExpiryDate(appProperties.getTokenGenerator().getPasswordTokenExpiry()));
    securityUser.setRememberMeToken(rememberMeToken);
    securityUserRepository.save(securityUser);

    return rememberMeToken;
  }

  @Override
  @Transactional
  public void clearRememeberMeToken(String rememberMeToken) {
    String loggerPrefix = getLoggerPrefix("clearRememeberMeToken", rememberMeToken);

    SecurityUser securityUser = securityUserRepository.findByRememberMeToken(rememberMeToken);
    if (securityUser != null) {
      securityUser.setRememberMeToken(new RememberMeToken());
      securityUserRepository.save(securityUser);
    } else {
      logger().warn(loggerPrefix + "Security user not found with token : " + rememberMeToken);
    }
  }

  @Override
  public PasswordResetToken getPasswordResetToken(String passwordResetToken) {
    SecurityUser securityUser = securityUserRepository.findByPasswordResetToken(passwordResetToken);
    if (securityUser != null) {
      return securityUser.getPasswordResetToken();
    } else {
      return null;
    }
  }

  @Override
  public SecurityUser getSecurityUserByRememberMeToken(String rememberMeToken) {
    return securityUserRepository.findByRememberMeToken(rememberMeToken);
  }

  @Override
  @Transactional
  public void changeUserPassword(SecurityUser securityUser, String newPassword) {
    securityUser.setPassword(passwordEncoder.encode(newPassword));
    securityUserRepository.save(securityUser);
  }

  @Override
  public boolean checkIfValidOldPassword(SecurityUser securityUser, String oldPassword) {
    return passwordEncoder.matches(oldPassword, securityUser.getPassword());
  }

  @Override
  @Transactional
  public String validateVerificationToken(String lastName, String firstName, String email, String nickName, String securityUserId,
      String verificationToken) {
    Optional<SecurityUser> _securityUser = securityUserRepository.findById(securityUserId);

    if (!_securityUser.isPresent()) {
      throw new ResourceNotFoundException("User", "id", securityUserId);
    }

    SecurityUser securityUser = _securityUser.get();
    if (securityUser.getVerificationToken() == null || (securityUser.getVerificationToken()
        .getToken() != null && !securityUser.getVerificationToken()
        .getToken().equals(verificationToken))) {
      return SecurityConst.TOKEN_INVALID;
    }

    final Calendar cal = Calendar.getInstance();
    if ((securityUser.getVerificationToken().getExpiryDate()
        .getTime()
        - cal.getTime()
        .getTime()) <= 0) {
      securityUser.setVerificationToken(new VerificationToken());
      return SecurityConst.TOKEN_EXPIRED;
    }
    securityUser.setEmail(email);
    securityUser.setLastName(lastName);
    securityUser.setFirstName(firstName);
    securityUser.setNickName(nickName);
    securityUser.setVerificationToken(new VerificationToken());
    securityUser.setIsActivated(true);
    // tokenRepository.delete(verificationToken);
    securityUserRepository.save(securityUser);
    return SecurityConst.TOKEN_VALID;
  }

  @Override
  @Transactional
  public String validatePasswordToken(String username, String passwordResetToken,
      String newPassword) {
    Optional<SecurityUser> _securityUser = securityUserRepository.findByUsername(username);

    if (!_securityUser.isPresent()) {
      throw new UsernameNotFoundException(username);
    }

    SecurityUser securityUser = _securityUser.get();
    if (securityUser.getPasswordResetToken() == null || !securityUser.getPasswordResetToken()
        .getToken().equals(passwordResetToken)) {
      return SecurityConst.TOKEN_INVALID;
    }

    final Calendar cal = Calendar.getInstance();
    if ((securityUser.getPasswordResetToken().getExpiryDate()
        .getTime()
        - cal.getTime()
        .getTime()) <= 0) {
      securityUser.setPasswordResetToken(new PasswordResetToken());
      securityUserRepository.save(securityUser);
      return SecurityConst.TOKEN_EXPIRED;
    }
    securityUser.setPassword(passwordEncoder.encode(newPassword));
    securityUser.setPasswordResetToken(new PasswordResetToken());
    securityUserRepository.save(securityUser);

    return SecurityConst.TOKEN_VALID;
  }

  @Override
  @Transactional
  public void deleteVerificationTokenByExpiryDateLessThan(Date now) {
    securityUserRepository.deleteVerificationTokenByExpiryDateLessThan(now);
  }

  @Override
  @Transactional
  public void deletePasswordResetTokenByExpiryDateLessThan(Date now) {
    securityUserRepository.deletePasswordResetTokenByExpiryDateLessThan(now);
  }

  @Override
  @Transactional
  public void deleteRemeberByTokenByExpiryDateLessThan(Date now) {
    securityUserRepository.deleteRememberMeTokenByExpiryDateLessThan(now);
  }

  private String getNewVerificationToken() {
    Integer number = Integer.valueOf(randon.nextInt(999999 - 100000) + 100000);
    SecurityUser existingToken = securityUserRepository.findByVerificationToken(number.toString());
    if (existingToken != null) {
      return getNewVerificationToken();
    } else {
      return number.toString();
    }
  }

  private String getNewRememberMeToken() {
    String token = UUID.randomUUID().toString();
    SecurityUser existingToken = securityUserRepository.findByRememberMeToken(token);
    if (existingToken != null) {
      return getNewRememberMeToken();
    } else {
      return token;
    }
  }

  private Date calculateExpiryDate(final int expiryTimeInMinutes) {
    final Calendar cal = Calendar.getInstance();
    cal.setTimeInMillis(new Date().getTime());
    cal.add(Calendar.MINUTE, expiryTimeInMinutes);
    return new Date(cal.getTime().getTime());
  }

  private void throwIfDeletingSelf(SecurityUser user) {
    if (AppContextThread.getCurrentSecurityUserId().equals(user.getId())) {
      throw new UserFriendlyDataException(DELETING_SELF_NOT_PERMITTED);
    }
  }

  private void throwIfUsernameExists(String username) {
    Optional<SecurityUser> existingUser = securityUserRepository.findByUsername(username);
    existingUser.ifPresent((user) -> {
      throw new IllegalArgumentException(USER_EXISTS);
    });
  }

  private void throwIfUserLocked(SecurityUser entity) {
    if (entity != null && entity.getIsAccountLocked() && SecurityUtils.isUserLoggedIn()
        && !SecurityUtils.hasRole(
        org.wannagoframework.dto.utils.SecurityConst.ROLE_SYSTEM)) {
      throw new UserFriendlyDataException(MODIFY_LOCKED_USER_NOT_PERMITTED);
    }
  }
}
