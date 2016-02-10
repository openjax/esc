package org.safris.commons.jetty;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import javax.servlet.annotation.ServletSecurity;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;

import org.eclipse.jetty.security.ConstraintMapping;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.security.HashLoginService;
import org.eclipse.jetty.security.SecurityHandler;
import org.eclipse.jetty.security.authentication.BasicAuthenticator;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.server.handler.ResourceHandler;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.resource.Resource;
import org.eclipse.jetty.util.security.Constraint;
import org.eclipse.jetty.util.security.Credential;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.safris.commons.lang.PackageLoader;
import org.safris.commons.lang.Resources;

public class EmbeddedServer {
  private static final Logger logger = Logger.getLogger(EmbeddedServer.class.getName());

  private static Connector makeConnector(final org.eclipse.jetty.server.Server server, final int port, final String keyStorePath, final String keyStorePassword) {
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
//    sslContextFactory.setKeyManagerPassword("123456");

    final ServerConnector connector = new ServerConnector(server, new SslConnectionFactory(sslContextFactory, "http/1.1"), new HttpConnectionFactory(https));
    connector.setPort(port);
    return connector;
  }

  private static void addServlet(final ServletContextHandler handler, final HttpServlet servlet) {
    final WebServlet annotation = servlet.getClass().getAnnotation(WebServlet.class);
    if (annotation == null)
      throw new Error(servlet.getClass().getName() + " does not have a @" + WebServlet.class.getName() + " annotation.");

    if (annotation.urlPatterns() == null || annotation.urlPatterns().length == 0)
      throw new Error(servlet.getClass().getName() + " does not have urlPatterns parameter in the @" + WebServlet.class.getName() + " annotation.");

    logger.info(servlet.getClass().getName() + " " + Arrays.toString(annotation.urlPatterns()));
    for (final String urlPattern : annotation.urlPatterns())
      handler.addServlet(new ServletHolder(servlet), urlPattern);
  }

  private static void addAllServlets(final Package pkg, final ServletContextHandler handler, final Constraint constraint) {
    try {
      final Set<Class<?>> classes = PackageLoader.getSystemPackageLoader().loadPackage(pkg, false);
      for (final Class<?> cls : classes) {
        if (HttpServlet.class.isAssignableFrom(cls)) {
          final HttpServlet servlet = (HttpServlet)cls.newInstance();

          final ServletSecurity servletSecurity = cls.getAnnotation(ServletSecurity.class);
          if (servletSecurity != null)
            addServlet(handler, constraint, servlet); // FIXME: Finish this! Make this code determine the exact security constraints to apply!
          else
            addServlet(handler, servlet);
        }
      }
    }
    catch (final Exception e) {
      throw new Error(e);
    }
  }

  public static void addServlet(final ServletContextHandler handler, final Constraint constraint, final HttpServlet servlet) {
    final WebServlet annotation = servlet.getClass().getAnnotation(WebServlet.class);
    if (annotation == null) {
      logger.warning(servlet.getClass().getSimpleName() + " is missing a @WebServlet annotation, so its urlPatterns spec is unknown");
      return;
    }

    if (annotation.urlPatterns() == null || annotation.urlPatterns().length == 0) {
      logger.warning(servlet.getClass().getSimpleName() + " is missing the urlPatterns spec in its @WebServlet annotation");
      return;
    }

    for (final String urlPattern : annotation.urlPatterns()) {
      final ConstraintMapping constraintMapping = new ConstraintMapping();
      constraintMapping.setConstraint(constraint);
      constraintMapping.setPathSpec(urlPattern);
      final SecurityHandler securityHandler = handler.getSecurityHandler();
      if (!(securityHandler instanceof ConstraintSecurityHandler))
        throw new Error("SecurityHandler of ServletContextHandler must be a ConstraintSecurityHandler, did you call setConstraintSecurityHandler()?");

      ((ConstraintSecurityHandler)securityHandler).addConstraintMapping(constraintMapping);
    }

    logger.info(servlet.getClass().getSimpleName() + " [" + handler.getSecurityHandler().getLoginService().getName() + "]: " + Arrays.toString(annotation.urlPatterns()));
    addServlet(handler, servlet);
  }

  private static final Map<String,Map<String,Constraint>> roleToConstraint = new HashMap<String,Map<String,Constraint>>();

  private static Constraint getConstraint(final Map<String,Constraint> authTypeToConstraint, final String authType, final String role) {
    Constraint constraint = authTypeToConstraint.get(authType);
    if (constraint != null)
      return constraint;

    synchronized (authTypeToConstraint) {
      constraint = authTypeToConstraint.get(authType);
      if (constraint != null)
        return constraint;

      authTypeToConstraint.put(authType, constraint = new Constraint(authType, role));
      constraint.setAuthenticate(true);
      return constraint;
    }
  }

  private static Constraint getBasicAuthConstraint(final String role) {
    Map<String,Constraint> authTypeToConstraint = roleToConstraint.get(role);
    if (authTypeToConstraint == null) {
      synchronized (roleToConstraint) {
        authTypeToConstraint = roleToConstraint.get(role);
        if (authTypeToConstraint == null)
          roleToConstraint.put(role, authTypeToConstraint = new HashMap<String,Constraint>());
      }
    }

    return getConstraint(authTypeToConstraint, Constraint.__BASIC_AUTH, role);
  }

  private static void setConstraintSecurityHandler(final ServletContextHandler handler, final String realm, final String role, final String username, final String password) {
    final HashLoginService loginService = new HashLoginService(realm);
    loginService.putUser(username, Credential.getCredential(password), new String[] {role});

    final ConstraintSecurityHandler securityHandler = new ConstraintSecurityHandler();
    securityHandler.setAuthenticator(new BasicAuthenticator());
    securityHandler.setRealmName(realm);
    securityHandler.setLoginService(loginService);

    handler.setSecurityHandler(securityHandler);
  }

  private final org.eclipse.jetty.server.Server server = new org.eclipse.jetty.server.Server();

  public EmbeddedServer(final String username, final String password, final int port, final String keyStorePath, final String keyStorePassword, final boolean externalResourcesAccess) {
    server.setConnectors(new Connector[] {makeConnector(server, port, keyStorePath, keyStorePassword)});

    final ServletContextHandler servletContextHandler = new ServletContextHandler(ServletContextHandler.SESSIONS);
    final Constraint basicAuthConstraint = getBasicAuthConstraint("user");
    setConstraintSecurityHandler(servletContextHandler, "Restricted", "user", username, password);
    addAllServlets(Package.getPackage(""), servletContextHandler, basicAuthConstraint);

    final HandlerList handlerList = new HandlerList();

    if (externalResourcesAccess) {
      // FIXME: HACK: Why cannot I just get the "/" resource? In the IDE it works, but in the stand-alone jar, it does not
      try {
        final String configResourcePath = Resources.getResource("config.xml").getURL().toExternalForm();
        final URL rootResourceURL = new URL(configResourcePath.substring(0, configResourcePath.length() - "config.xml".length()));

        final ResourceHandler resourceHandler = new ResourceHandler();
        resourceHandler.setDirectoriesListed(true);
        resourceHandler.setBaseResource(Resource.newResource(rootResourceURL));

        handlerList.addHandler(resourceHandler);
      }
      catch (final MalformedURLException e) {
        throw new Error(e);
      }
    }

    handlerList.addHandler(servletContextHandler);

    server.setHandler(handlerList);
  }

  public void start() throws Exception {
    server.start();
  }

  public void join() throws InterruptedException {
    server.join();
  }
}