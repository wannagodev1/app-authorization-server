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


package org.wannagoframework.authorization.task;

import java.time.Instant;
import java.util.Date;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.wannagoframework.authorization.service.SecurityUserService;

/**
 * @author WannaGo Dev1.
 * @version 1.0
 * @since 2019-07-09
 */
@Service
@Transactional
public class TokensPurgeTask {

  private final SecurityUserService securityUserService;

  public TokensPurgeTask(
      SecurityUserService securityUserService) {
    this.securityUserService = securityUserService;
  }

  @Scheduled(cron = "${app.tokenGenerator.purgeCronExpression}")
  public void purgeExpired() {

    Date now = Date.from(Instant.now());

    securityUserService.deleteVerificationTokenByExpiryDateLessThan(now);
    securityUserService.deletePasswordResetTokenByExpiryDateLessThan(now);
    securityUserService.deleteRemeberByTokenByExpiryDateLessThan(now);
  }
}