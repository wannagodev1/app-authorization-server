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
import org.wannagoframework.commons.utils.HasLogger;
import org.wannagoframework.authorization.domain.SmsActionEnum;
import org.wannagoframework.authorization.domain.SmsTemplate;
import org.wannagoframework.authorization.repository.SmsTemplateRepository;

@Service
@Transactional(readOnly = true)
public class SmsTemplateServiceImpl implements SmsTemplateService, HasLogger {

  private final SmsTemplateRepository smsTemplateRepository;

  public SmsTemplateServiceImpl(
      SmsTemplateRepository smsTemplateRepository) {
    this.smsTemplateRepository = smsTemplateRepository;
  }


  @Override
  public Page<SmsTemplate> findAnyMatching(String filter, Pageable pageable) {
    String loggerString = getLoggerPrefix("findAnyMatching");
    logger().debug(loggerString + "In = " + filter);
    Page<SmsTemplate> result;

    if (StringUtils.isNotBlank(filter)) {
      result = smsTemplateRepository.findByCriteria(filter, pageable);
    } else {
      result = smsTemplateRepository.findAll(pageable);
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
      result = smsTemplateRepository.countByCriteria(filter);
    } else {
      result = smsTemplateRepository.count();
    }

    logger().debug(loggerString + "Out = " + result);
    return result;
  }

  @Override
  public long countBySmsAction(SmsActionEnum smsAction) {
    return smsTemplateRepository.countBySmsActionAndIsActiveIsTrue(smsAction);
  }

  @Override
  public Optional<SmsTemplate> findBySmsAction(SmsActionEnum smsAction, String iso3Language) {
    Optional<SmsTemplate> result = Optional.empty();
    if (StringUtils.isNotBlank(iso3Language)) {
      result = smsTemplateRepository
          .findBySmsActionAndIso3LanguageAndIsActiveIsTrue(smsAction, iso3Language);
    }
    if (result.isEmpty()) {
      result = smsTemplateRepository.findBySmsActionAndIsActiveIsTrue(smsAction);
    }
    return result;
  }

  @Override
  @Transactional
  public SmsTemplate add(SmsTemplate smsTemplate) {
    return smsTemplateRepository.save(smsTemplate);
  }

  @Override
  @Transactional
  public SmsTemplate update(SmsTemplate smsTemplate) {
    return add(smsTemplate);
  }

  @Override
  @Transactional
  public void delete(SmsTemplate smsTemplate) {
    if (smsTemplate.getIsActive()) {
      smsTemplate.setIsActive(false);
      smsTemplateRepository.save(smsTemplate);
    } else {
      smsTemplateRepository.delete(smsTemplate);
    }
  }

  @Override
  public MongoRepository<SmsTemplate, String> getRepository() {
    return smsTemplateRepository;
  }
}
