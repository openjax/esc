/* Copyright (c) 2017 OpenJAX
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * You should have received a copy of The MIT License (MIT) along with this
 * program. If not, see <http://opensource.org/licenses/MIT/>.
 */

package org.openjax.esc;

import java.io.Serializable;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * A named realm of roles and credentials.
 */
public class Realm implements Cloneable, Serializable {
  private final HashMap<String,String> credentials = new HashMap<>();
  private final HashSet<String> roles = new HashSet<>();
  private final String name;

  /**
   * Creates a new {@link Realm} with the specified name.
   *
   * @param name The name.
   */
  public Realm(final String name) {
    this.name = name;
  }

  /**
   * Copy constructor.
   *
   * @param copy The {@link Realm} to copy.
   * @throws NullPointerException If {@code copy} is null.
   */
  protected Realm(final Realm copy) {
    this.name = copy.name;
    this.credentials.putAll(copy.credentials);
    this.roles.addAll(copy.roles);
  }

  /**
   * Returns the name of the realm.
   *
   * @return The name of the realm.
   */
  public String getName() {
    return name;
  }

  /**
   * Adds a role to this {@link Realm}.
   *
   * @param role The role.
   */
  public void addRole(final String role) {
    roles.add(role);
  }

  /**
   * Returns the set of roles of this {@link Realm}.
   *
   * @return The set of roles of this {@link Realm}.
   */
  public Set<String> getRoles() {
    return roles;
  }

  /**
   * Adds or reassigns a username/password credential to this {@link Realm}.
   *
   * @param username The username.
   * @param password The password.
   */
  public void addCredential(final String username, final String password) {
    credentials.put(username, password);
  }

  /**
   * Returns the credentials of this {@code Realm}.
   *
   * @return The credentials of this {@code Realm}.
   */
  public Map<String,String> getCredentials() {
    return credentials;
  }

  @Override
  public Realm clone() {
    return new Realm(this);
  }

  @Override
  public boolean equals(final Object obj) {
    if (this == obj)
      return true;

    if (!(obj instanceof Realm))
      return false;

    final Realm that = (Realm)obj;
    return Objects.equals(name, that.name) && credentials.equals(that.credentials) && roles.equals(that.roles);
  }

  @Override
  public int hashCode() {
    int hashCode = 1;
    hashCode = 31 * hashCode + credentials.hashCode();
    hashCode = 31 * hashCode + roles.hashCode();
    hashCode = 31 * hashCode + Objects.hashCode(name);
    return hashCode;
  }
}