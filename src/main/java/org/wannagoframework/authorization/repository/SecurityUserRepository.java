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

import java.util.Date;
import java.util.Optional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;
import org.wannagoframework.authorization.domain.SecurityUser;

@Repository
public interface SecurityUserRepository extends MongoRepository<SecurityUser, String> {

  Optional<SecurityUser> findByEmail(String email);

  Boolean existsByEmail(String email);

  Optional<SecurityUser> findByUsername(String username);

  @Query("{'username':{'$regex':'?0','$options':'i'}, 'isActive': ?1}")
  Page<SecurityUser> findByUsernameLikeAndIsActive(String filter, Boolean showInactive,
      Pageable pageable);

  @Query("{'username':{'$regex':'?0','$options':'i'}}")
  Page<SecurityUser> findByUsernameLike(String filter, Pageable pageable);

  Page<SecurityUser> findByIsActive(Boolean showInactive, Pageable pageable);

  SecurityUser getByUsernameIgnoreCase(String username);

  @Query(value = "{'username':{'$regex':'?0','$options':'i'}, 'isActive': ?1}", count = true)
  long countByUsernameLikeAndIsActive(String filter, Boolean showInactive);

  @Query(value = "{'username':{'$regex':'?0','$options':'i'}}", count = true)
  long countByUsername(String filter);

  long countByIsActive(Boolean showInactive);

  boolean existsByMobileNumber(String mobileNumber);

  @Query("{'verificationToken.token': ?0}")
  SecurityUser findByVerificationToken(String verificationToken);

  @Query("{'rememberMeToken.token': ?0}")
  SecurityUser findByRememberMeToken(String rememberMeToken);

  @Query("{'passwordResetToken.token': ?0}")
  SecurityUser findByPasswordResetToken(String passwordResetToken);

  @Query(value = "{'verificationToken.expiryDate': {$lte: ?0}}", delete = true)
  void deleteVerificationTokenByExpiryDateLessThan(Date now);

  @Query(value = "{'passwordResetToken.expiryDate': {$lte: ?0}}", delete = true)
  void deletePasswordResetTokenByExpiryDateLessThan(Date now);

  @Query(value = "{'rememberMeToken.expiryDate': {$lte: ?0}}", delete = true)
  void deleteRememberMeTokenByExpiryDateLessThan(Date now);
}
