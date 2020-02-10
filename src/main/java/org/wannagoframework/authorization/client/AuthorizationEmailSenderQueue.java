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


package org.wannagoframework.authorization.client;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jms.core.JmsTemplate;
import org.springframework.stereotype.Component;
import org.wannagoframework.authorization.config.JmsConfig;
import org.wannagoframework.dto.domain.notification.Mail;
import org.wannagoframework.dto.domain.notification.Sms;

/**
 * @author WannaGo Dev1.
 * @version 1.0
 * @since 2019-07-02
 */
@Slf4j
@Component
public class AuthorizationEmailSenderQueue {

  @Autowired
  private JmsTemplate jmsTemplate;

  @Value("${spring.application.name}")
  private String appName;

  /**
   * Send the given mail by JMS through the {@link JmsConfig#JMS_CHANNEL_MAILBOX} channel.
   *
   * @param mail the email to send
   * @author Wannago dev1.
   * @see JmsConfig
   */
  public void sendMail(final Mail mail) {
    log.debug("Sending email {} to {} - {}", mail.getSubject(), mail.getTo(), appName);
    mail.setApplicationName(appName);
    jmsTemplate.send(JmsConfig.JMS_CHANNEL_MAILBOX, session -> session.createObjectMessage(mail));
  }

  /**
   * Send the given SMS by JMS through the {@link JmsConfig#JMS_CHANNEL_SMS} channel.
   *
   * @param sms the SMS to send
   * @author Wannago dev1.
   * @see JmsConfig
   */
  public void sendSms(Sms sms) {
    log.debug("Sending SMS to {} - {}", sms.getPhoneNumber(), appName);
    sms.setApplicationName(appName);
    jmsTemplate.send(JmsConfig.JMS_CHANNEL_SMS, session -> session.createObjectMessage(sms));
  }
}
