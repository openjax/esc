/* Copyright (c) 2017 lib4j
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

package org.libx4j.jetty;

import java.io.Serializable;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class Realm implements Cloneable, Serializable {
  private static final long serialVersionUID = 5903086620776103606L;

  private final Map<String,String> credentials = new HashMap<String,String>();
  private final Set<String> roles = new HashSet<String>();
  private final String name;

  public Realm(final String name) {
    this.name = name;
  }

  private Realm(final Realm copy) {
    this.name = copy.name;
    this.credentials.putAll(copy.credentials);
    this.roles.addAll(copy.roles);
  }

  public String getName() {
    return this.name;
  }

  public void addRole(final String role) {
    this.roles.add(role);
  }

  public Set<String> getRoles() {
    return roles;
  }

  public void addCredential(final String username, final String password) {
    this.credentials.put(username, password);
  }

  public Map<String,String> getCredentials() {
    return this.credentials;
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
    return (name != null ? name.equals(that.name) : that.name == null) && credentials.equals(that.credentials) && roles.equals(that.roles);
  }

  @Override
  public int hashCode() {
    int hashCode = 7;
    hashCode ^= 31 * credentials.hashCode();
    hashCode ^= 31 * roles.hashCode();
    hashCode ^= 31 * name.hashCode();
    return hashCode;
  }
}