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

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.module.afterburner.AfterburnerModule;
import java.time.Instant;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.wannagoframework.commons.converter.DateConverter.Deserialize;
import org.wannagoframework.commons.converter.DateConverter.Serialize;
import org.zalando.problem.ProblemModule;
import org.zalando.problem.violations.ConstraintViolationProblemModule;

@Configuration
public class JacksonConfiguration {

  /**
   * Support for Java date and time API.
   *
   * @return the corresponding Jackson module.
   */
  @Bean
  public JavaTimeModule javaTimeModule() {
    return new JavaTimeModule();
  }

  @Bean
  public Jdk8Module jdk8TimeModule() {
    return new Jdk8Module();
  }

  /**
   * Jackson Afterburner module to speed up serialization/deserialization.
   */
  @Bean
  public AfterburnerModule afterburnerModule() {
    return new AfterburnerModule();
  }

  /**
   * Module for serialization/deserialization of RFC7807 Problem.
   */
  @Bean
  public ProblemModule problemModule() {
    return new ProblemModule();
  }

  /**
   * Module for serialization/deserialization of ConstraintViolationProblem.
   */
  @Bean
  public ConstraintViolationProblemModule constraintViolationProblemModule() {
    return new ConstraintViolationProblemModule();
  }

  @Bean
  public ObjectMapper jsonObjectMapper() {
    return Jackson2ObjectMapperBuilder.json()
        .modules(module(), new JavaTimeModule())
        .build();
  }

  public Module module() {
    SimpleModule module = new SimpleModule();
    module.addSerializer(Instant.class,
        new Serialize());               // register as serialize class for Instant.class
    module.addDeserializer(Instant.class,
        new Deserialize());          //  register as deserialize class for Instant.class
    return module;
  }
}
