/* Copyright (c) 2016 lib4j
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

import java.io.IOException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.security.HashLoginService;
import org.eclipse.jetty.security.authentication.BasicAuthenticator;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.server.handler.ResourceHandler;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.util.resource.Resource;
import org.eclipse.jetty.util.security.Constraint;
import org.eclipse.jetty.util.security.Credential;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.lib4j.lang.Resources;
import org.libx4j.jetty.servlet.xe.$se_realm;

public abstract class EmbeddedServletContext {
  private static final Map<String,Map<String,Constraint>> roleToConstraint = new HashMap<String,Map<String,Constraint>>();

  private static Constraint getConstraint(final Map<String,Constraint> authTypeToConstraint, final String authType, final String role) {
    Constraint constraint = authTypeToConstraint.get(authType);
    if (constraint != null)
      return constraint;

    authTypeToConstraint.put(authType, constraint = new Constraint(authType, role));
    constraint.setAuthenticate(true);
    return constraint;
  }

  protected static Constraint getBasicAuthConstraint(final String authType, final String role) {
    Map<String,Constraint> authTypeToConstraint = roleToConstraint.get(role);
    if (authTypeToConstraint == null)
      roleToConstraint.put(role, authTypeToConstraint = new HashMap<String,Constraint>());

    return getConstraint(authTypeToConstraint, authType, role);
  }

  private static Connector makeConnector(final Server server, final int port, final String keyStorePath, final String keyStorePassword) {
    if (keyStorePath == null || keyStorePassword == null) {
      final ServerConnector connector = new ServerConnector(server);
      connector.setPort(port);
      return connector;
    }

    final HttpConfiguration https = new HttpConfiguration();
    https.addCustomizer(new SecureRequestCustomizer());

    final SslContextFactory sslContextFactory = new SslContextFactory();
    sslContextFactory.setKeyStorePath(Resources.getResource(keyStorePath).getURL().toExternalForm());
    sslContextFactory.setKeyStorePassword(keyStorePassword);

    final ServerConnector connector = new ServerConnector(server, new SslConnectionFactory(sslContextFactory, "http/1.1"), new HttpConnectionFactory(https));
    connector.setPort(port);
    return connector;
  }

  protected static ServletContextHandler createServletContextHandler(final $se_realm realm) {
    final ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);

    final ConstraintSecurityHandler security = new ConstraintSecurityHandler();
    if (realm != null) {
      final HashLoginService login = new HashLoginService(realm._name$().text());
      for (final $se_realm._credential credential : realm._credential())
        for (final String role : credential._roles$().text())
          login.putUser(credential._username$().text(), Credential.getCredential(credential._password$().text()), new String[] {role});

      security.setRealmName(realm._name$().text());
      security.setLoginService(login);
      security.setAuthenticator(new BasicAuthenticator());
    }

    context.setSecurityHandler(security);
    return context;
  }

  private final Server server = new Server();

  public EmbeddedServletContext(final int port, final String keyStorePath, final String keyStorePassword, final boolean externalResourcesAccess, final ServletContextHandler context) {
    server.setConnectors(new Connector[] {makeConnector(server, port, keyStorePath, keyStorePassword)});

    final HandlerList handlerList = new HandlerList();

    if (externalResourcesAccess) {
      // FIXME: HACK: Why cannot I just get the "/" resource? In the IDE it works, but in the stand-alone jar, it does not
      try {
        final String resourceName = getClass().getName().replace('.', '/') + ".class";
        final String configResourcePath = Resources.getResource(resourceName).getURL().toExternalForm();
        final URL rootResourceURL = new URL(configResourcePath.substring(0, configResourcePath.length() - resourceName.length()));

        final ResourceHandler resourceHandler = new ResourceHandler();
        resourceHandler.setDirectoriesListed(true);
        resourceHandler.setBaseResource(Resource.newResource(rootResourceURL));

        handlerList.addHandler(resourceHandler);
      }
      catch (final IOException e) {
        throw new UnsupportedOperationException(e);
      }
    }

    handlerList.addHandler(context);
    server.setHandler(handlerList);
  }

  public void start() throws Exception {
    server.start();
  }

  public void join() throws InterruptedException {
    server.join();
  }
}