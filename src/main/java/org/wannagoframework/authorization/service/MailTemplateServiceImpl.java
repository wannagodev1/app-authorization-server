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

import java.util.Optional;
import org.apache.commons.lang3.StringUtils;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.wannagoframework.authorization.domain.MailActionEnum;
import org.wannagoframework.authorization.domain.MailTemplate;
import org.wannagoframework.authorization.repository.MailTemplateRepository;
import org.wannagoframework.commons.utils.HasLogger;

@Service
@Transactional(readOnly = true)
public class MailTemplateServiceImpl implements MailTemplateService, HasLogger {

  private final MailTemplateRepository mailTemplateRepository;

  public MailTemplateServiceImpl(
      MailTemplateRepository mailTemplateRepository) {
    this.mailTemplateRepository = mailTemplateRepository;
  }


  @Override
  public Page<MailTemplate> findAnyMatching(String filter, Pageable pageable) {
    String loggerString = getLoggerPrefix("findAnyMatching");
    logger().debug(loggerString + "In = " + filter);
    Page<MailTemplate> result;

    if (StringUtils.isNotBlank(filter)) {
      result = mailTemplateRepository.findByCriteria(filter, pageable);
    } else {
      result = mailTemplateRepository.findAll(pageable);
    }

    logger().debug(loggerString + "Out = " + result);

    return result;
  }


  @Override
  public long countAnyMatching(String filter) {
    String loggerString = getLoggerPrefix("countAnyMatching");
    logger().debug(loggerString + "In = " + filter);
    long result;
    if (StringUtils.isNotBlank(filter)) {
      result = mailTemplateRepository.countByCriteria(filter);
    } else {
      result = mailTemplateRepository.count();
    }

    logger().debug(loggerString + "Out = " + result);
    return result;
  }

  @Override
  public long countByMailAction(MailActionEnum mailAction) {
    return mailTemplateRepository.countByMailActionAndIsActiveIsTrue(mailAction);
  }

  @Override
  public Optional<MailTemplate> findByMailAction(MailActionEnum mailAction, String iso3Language) {
    Optional<MailTemplate> result = Optional.empty();
    if (StringUtils.isNotBlank(iso3Language)) {
      result = mailTemplateRepository
          .findByMailActionAndIso3LanguageAndIsActiveIsTrue(mailAction, iso3Language);
    }
    if (result.isEmpty()) {
      result = mailTemplateRepository.findByMailActionAndIsActiveIsTrue(mailAction);
    }
    return result;
  }

  @Override
  @Transactional
  public MailTemplate add(MailTemplate mailTemplate) {
    return mailTemplateRepository.save(mailTemplate);
  }

  @Override
  @Transactional
  public MailTemplate update(MailTemplate mailTemplate) {
    return add(mailTemplate);
  }

  @Override
  @Transactional
  public void delete(MailTemplate mailTemplate) {
    if (mailTemplate.getIsActive()) {
      mailTemplate.setIsActive(false);
      mailTemplateRepository.save(mailTemplate);
    } else {
      mailTemplateRepository.delete(mailTemplate);
    }
  }

  @Override
  public MongoRepository<MailTemplate, String> getRepository() {
    return mailTemplateRepository;
  }
}
