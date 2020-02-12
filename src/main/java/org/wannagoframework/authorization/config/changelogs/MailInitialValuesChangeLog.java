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


package org.wannagoframework.authorization.config.changelogs;

import com.github.mongobee.changeset.ChangeLog;
import com.github.mongobee.changeset.ChangeSet;
import java.util.Locale;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.stereotype.Component;
import org.wannagoframework.authorization.domain.MailActionEnum;
import org.wannagoframework.authorization.domain.MailTemplate;
import org.wannagoframework.authorization.domain.SmsActionEnum;
import org.wannagoframework.authorization.domain.SmsTemplate;

@Component
@ChangeLog
public class MailInitialValuesChangeLog {

  @ChangeSet(order = "001", id = "insertVerificationCodeEmail", author = "Wanna Go Dev1")
  public void insertVerificationCodeEmail(MongoTemplate mongoTemplate) {
    MailTemplate notificationMailTemplate = new MailTemplate();
    notificationMailTemplate.setMailAction(MailActionEnum.EMAIL_VERIFICATION.name());
    notificationMailTemplate.setBody("Hi,<br/>"
        + "<br/>"
        + "Thank you for signing up to Wanna Play. Please confirm your email address to activate your account.\n"
        + "<br/>"
        + "Verification code: ${verificationCode}");
    notificationMailTemplate.setSubject("Welcome to EnjoyIt");
    notificationMailTemplate.setFrom("<Enjoy It> no-reply@enjoyit.ma");
    notificationMailTemplate.setIso3Language(Locale.ENGLISH.getLanguage());
    notificationMailTemplate.setName("Verification Code");

    mongoTemplate.save(notificationMailTemplate);
  }

  @ChangeSet(order = "002", id = "insertVerificationCodeSms", author = "Wanna Go Dev1")
  public void insertVerificationCodeSms(MongoTemplate mongoTemplate) {
    SmsTemplate notificationSmsTemplate = new SmsTemplate();
    notificationSmsTemplate.setSmsAction(SmsActionEnum.SMS_VERIFICATION.name());
    notificationSmsTemplate.setBody("Code Enjoy-It ${verificationCode}");
    notificationSmsTemplate.setIso3Language(Locale.ENGLISH.getLanguage());
    notificationSmsTemplate.setName("Verification Code");

    mongoTemplate.save(notificationSmsTemplate);
  }

  @ChangeSet(order = "003", id = "insertForgetPasswordEmail", author = "Wanna Go Dev1")
  public void insertForgetPasswordEmail(MongoTemplate mongoTemplate) {
    MailTemplate notificationMailTemplate = new MailTemplate();
    notificationMailTemplate.setMailAction(MailActionEnum.EMAIL_FORGET_PASSWORD.name());
    notificationMailTemplate.setBody("Hi,<br/>"
        + "<br/>"
        + "Reset code: ${resetCode}");
    notificationMailTemplate.setSubject("Password reset for EnjoyIt");
    notificationMailTemplate.setFrom("<Enjoy It> no-reply@enjoyit.ma");
    notificationMailTemplate.setIso3Language(Locale.ENGLISH.getLanguage());
    notificationMailTemplate.setName("Forget Password Code");

    mongoTemplate.save(notificationMailTemplate);
  }

  @ChangeSet(order = "004", id = "insertForgetPasswordSms", author = "Wanna Go Dev1")
  public void insertForgetPasswordSms(MongoTemplate mongoTemplate) {
    SmsTemplate notificationSmsTemplate = new SmsTemplate();
    notificationSmsTemplate.setSmsAction(SmsActionEnum.SMS_FORGET_PASSWORD.name());
    notificationSmsTemplate.setBody("Reset Code Enjoy-It ${resetCode}");
    notificationSmsTemplate.setIso3Language(Locale.ENGLISH.getLanguage());
    notificationSmsTemplate.setName("Forget Password Code");

    mongoTemplate.save(notificationSmsTemplate);
  }

  @ChangeSet(order = "005", id = "createTransactionalCollections", author = "Wanna Go Dev1")
  public void createTransactionalCollections(MongoTemplate mongoTemplate) {
    //mongoTemplate.createCollection(Sms.class);
    //mongoTemplate.createCollection(Mail.class);

  }
}
