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


import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.transaction.annotation.Transactional;
import org.wannagoframework.authorization.domain.BaseEntity;
import org.wannagoframework.authorization.exception.EntityNotFoundException;

/**
 * @author WannaGo Dev1.
 * @version 1.0
 * @since 2019-03-26
 */
@Transactional(readOnly = true)
public interface BaseCrudService<T extends BaseEntity> {

  MongoRepository<T, String> getRepository();

  @Transactional()
  default T save(T entity) {
    return getRepository().save(entity);
  }

  @Transactional()
  default void delete(T entity) {
    if (entity == null) {
      throw new EntityNotFoundException();
    }
    getRepository().delete(entity);
  }

  @Transactional()
  default void delete(String id) {
    delete(load(id));
  }

  default long count() {
    return getRepository().count();
  }

  default T load(String id) {
    T entity = getRepository().findById(id).orElse(null);
    if (entity == null) {
      throw new EntityNotFoundException();
    }
    return entity;
  }

  default Iterable<T> findAll() {
    return getRepository().findAll();
  }
}
