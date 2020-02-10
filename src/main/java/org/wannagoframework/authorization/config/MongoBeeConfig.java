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


package org.wannagoframework.authorization.config;

import com.github.mongobee.Mongobee;
import com.mongodb.MongoClient;
import com.mongodb.MongoClientURI;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.core.env.Environment;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.wannagoframework.commons.utils.HasLogger;

@Configuration
@DependsOn("mongoTemplate")
public class MongoBeeConfig implements HasLogger {

  private static final String MONGODB_CHANGELOGS_PACKAGE = "org.wannagoframework.authorization.config.changelogs";

  @Autowired
  private Environment environment;

  @Bean
  public Mongobee mongobeeGlobal(MongoClient mongoClient, MongoTemplate mongoTemplate,
      org.springframework.boot.autoconfigure.mongo.MongoProperties mongoProperties) {
    String loggerPrefix = getLoggerPrefix("mongobeeGlobal");
    Mongobee mongobee = new Mongobee(mongoClient);
    mongobee.setChangelogCollectionName("dbChangelog");
    mongobee.setSpringEnvironment(environment);
    mongobee.setLockCollectionName("dbChangelogLock");
    MongoClientURI uri = new MongoClientURI(mongoProperties.getUri());
    logger().debug(loggerPrefix + "uri = " + mongoProperties.getUri());
    mongobee.setMongoClientURI(uri);
    logger().debug(loggerPrefix + "database = " + uri.getDatabase());
    mongobee.setDbName(uri.getDatabase());
    mongobee.setMongoTemplate(mongoTemplate);
    // package to scan for migrations
    mongobee.setChangeLogsScanPackage(MONGODB_CHANGELOGS_PACKAGE);
    mongobee.setEnabled(true);

    return mongobee;
  }
}
