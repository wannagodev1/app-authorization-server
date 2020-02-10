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


package org.wannagoframework.authorization.security.oauth2;

import java.util.Optional;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.wannagoframework.authorization.domain.AuthProviderEnum;
import org.wannagoframework.authorization.domain.SecurityUser;
import org.wannagoframework.authorization.domain.SecurityUserTypeEnum;
import org.wannagoframework.authorization.exception.OAuth2AuthenticationProcessingException;
import org.wannagoframework.authorization.repository.SecurityRoleRepository;
import org.wannagoframework.authorization.repository.SecurityUserRepository;
import org.wannagoframework.authorization.security.oauth2.user.OAuth2UserInfo;
import org.wannagoframework.authorization.security.oauth2.user.OAuth2UserInfoFactory;
import org.wannagoframework.commons.utils.OrikaBeanMapper;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

  private final SecurityUserRepository securityUserRepository;
  private final SecurityRoleRepository securityRoleRepository;
  private final OrikaBeanMapper mapperFacade;

  public CustomOAuth2UserService(
      SecurityUserRepository securityUserRepository,
      SecurityRoleRepository securityRoleRepository,
      OrikaBeanMapper mapperFacade) {
    this.securityUserRepository = securityUserRepository;
    this.securityRoleRepository = securityRoleRepository;
    this.mapperFacade = mapperFacade;
  }

  @Override
  public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest)
      throws OAuth2AuthenticationException {
    OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);

    try {
      return processOAuth2User(oAuth2UserRequest, oAuth2User);
    } catch (AuthenticationException ex) {
      throw ex;
    } catch (Exception ex) {
      // Throwing an instance of AuthenticationException will trigger the OAuth2AuthenticationFailureHandler
      throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
    }
  }

  private OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {
    OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory
        .getOAuth2UserInfo(oAuth2UserRequest.getClientRegistration().getRegistrationId(),
            oAuth2User.getAttributes());
    if (StringUtils.isEmpty(oAuth2UserInfo.getEmail())) {
      throw new OAuth2AuthenticationProcessingException("Email not found from OAuth2 provider");
    }

    Optional<SecurityUser> userOptional = securityUserRepository
        .findByEmail(oAuth2UserInfo.getEmail());
    SecurityUser user;
    if (userOptional.isPresent()) {
      user = userOptional.get();
      if (!user.getProvider().equals(
          AuthProviderEnum.get(oAuth2UserRequest.getClientRegistration().getRegistrationId()))) {
        throw new OAuth2AuthenticationProcessingException("Looks like you're signed up with " +
            user.getProvider() + " account. Please use your " + user.getProvider() +
            " account to login.");
      }
      user = updateExistingUser(user, oAuth2UserInfo);
    } else {
      user = registerNewUser(oAuth2UserRequest, oAuth2UserInfo);
    }

    org.wannagoframework.dto.domain.security.SecurityUser securityUserDTO = new org.wannagoframework.dto.domain.security.SecurityUser();
    mapperFacade.map(user, securityUserDTO);
    securityUserDTO.setAttributes(oAuth2User.getAttributes());

    return securityUserDTO;
  }

  private SecurityUser registerNewUser(OAuth2UserRequest oAuth2UserRequest,
      OAuth2UserInfo oAuth2UserInfo) {
    SecurityUser user = new SecurityUser();

    user.setProvider(
        AuthProviderEnum.get(oAuth2UserRequest.getClientRegistration().getRegistrationId()));
    user.setProviderId(oAuth2UserInfo.getId());
    user.setUsername(oAuth2UserInfo.getName());
    user.setEmail(oAuth2UserInfo.getEmail());
    user.setImageUrl(oAuth2UserInfo.getImageUrl());
    user.setUserType(SecurityUserTypeEnum.EXTERNAL);
    user.getRoles().add(securityRoleRepository.getByNameIgnoreCase("EXTERNAL"));
    return securityUserRepository.save(user);
  }

  private SecurityUser updateExistingUser(SecurityUser existingUser,
      OAuth2UserInfo oAuth2UserInfo) {
    existingUser.setUsername(oAuth2UserInfo.getName());
    existingUser.setImageUrl(oAuth2UserInfo.getImageUrl());
    return securityUserRepository.save(existingUser);
  }

}
