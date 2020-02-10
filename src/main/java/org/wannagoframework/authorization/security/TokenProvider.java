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


package org.wannagoframework.authorization.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import java.util.Date;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.stereotype.Service;
import org.wannagoframework.authorization.config.AppProperties;
import org.wannagoframework.dto.domain.security.SecurityUser;

@Service
public class TokenProvider {

  private static final Logger logger = LoggerFactory.getLogger(TokenProvider.class);

  private final AppProperties appProperties;
  private final KeyStoreKeyFactory keyStoreKeyFactory;
  private final ObjectMapper jsonObjectMapper;

  public TokenProvider(AppProperties appProperties,
      ObjectMapper jsonObjectMapper) {
    this.appProperties = appProperties;
    this.keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource("jwt.jks"),
        appProperties.getKeystore().getPassword().toCharArray());
    this.jsonObjectMapper = jsonObjectMapper;
  }

  public String createToken(Authentication authentication) {
    SecurityUser userPrincipal = (SecurityUser) authentication.getPrincipal();

    Date now = new Date();
    Date expiryDate = new Date(
        now.getTime() + appProperties.getAuth().getTokenExpirationMsec());

    final String authorities = userPrincipal.getAuthorities().stream()
        .map(GrantedAuthority::getAuthority)
        .collect(Collectors.joining(","));

    Claims claims = Jwts.claims();
    claims.setSubject(userPrincipal.getId());

    String securityUserJson = null;
    try {
      securityUserJson = jsonObjectMapper.writeValueAsString(userPrincipal);
      claims.put("securityUser", securityUserJson);
    } catch (JsonProcessingException e) {
      e.printStackTrace();
    }

    claims.put("user_name", userPrincipal.getUsername());
    claims.put("authorities", authorities);

    return Jwts.builder()
        .setClaims(claims)
        .setIssuedAt(new Date())
        .setExpiration(expiryDate)
        .signWith(SignatureAlgorithm.RS256, keyStoreKeyFactory.getKeyPair("jwt").getPrivate())
        .compact();
  }

  public String getUserIdFromToken(String token) {
    Claims claims = Jwts.parser()
        .setSigningKey(keyStoreKeyFactory.getKeyPair("jwt").getPublic())
        .parseClaimsJws(token)
        .getBody();

    return claims.getSubject();
  }

  public boolean validateToken(String authToken) {
    try {
      Jwts.parser().setSigningKey(keyStoreKeyFactory.getKeyPair("jwt").getPublic())
          .parseClaimsJws(authToken);
      return true;
    } catch (SignatureException ex) {
      logger.error("Invalid JWT signature");
    } catch (MalformedJwtException ex) {
      logger.error("Invalid JWT token");
    } catch (ExpiredJwtException ex) {
      logger.error("Expired JWT token");
    } catch (UnsupportedJwtException ex) {
      logger.error("Unsupported JWT token");
    } catch (IllegalArgumentException ex) {
      logger.error("JWT claims string is empty.");
    }
    return false;
  }

}
