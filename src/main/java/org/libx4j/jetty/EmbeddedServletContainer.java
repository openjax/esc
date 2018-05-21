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
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

import javax.servlet.DispatcherType;
import javax.servlet.Filter;
import javax.servlet.MultipartConfigElement;
import javax.servlet.annotation.ServletSecurity;
import javax.servlet.annotation.WebFilter;
import javax.servlet.annotation.WebInitParam;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;

import org.eclipse.jetty.security.ConstraintMapping;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.security.HashLoginService;
import org.eclipse.jetty.security.SecurityHandler;
import org.eclipse.jetty.security.UserStore;
import org.eclipse.jetty.security.authentication.BasicAuthenticator;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.Slf4jRequestLog;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.server.handler.HandlerCollection;
import org.eclipse.jetty.server.handler.RequestLogHandler;
import org.eclipse.jetty.server.handler.ResourceHandler;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.resource.Resource;
import org.eclipse.jetty.util.security.Constraint;
import org.eclipse.jetty.util.security.Credential;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.lib4j.lang.PackageLoader;
import org.lib4j.lang.PackageNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EmbeddedServletContainer implements AutoCloseable {
  private static final Logger logger = LoggerFactory.getLogger(EmbeddedServletContainer.class);

  private static final Set<Class<? extends HttpServlet>> addedServletClasses = new HashSet<Class<? extends HttpServlet>>();
  private static final Set<Class<? extends Filter>> addedFilterClasses = new HashSet<Class<? extends Filter>>();
  private static final String[] excludeStartsWith = {"jdk", "java", "javax", "com.sun", "sun", "org.w3c", "org.xml", "org.jvnet", "org.joda", "org.jcp", "apple.security"};

  private static UncaughtServletExceptionHandler uncaughtServletExceptionHandler;

  private static boolean acceptPackage(final Package pkg) {
    for (int i = 0; i < excludeStartsWith.length; i++)
      if (pkg.getName().startsWith(excludeStartsWith[i] + "."))
        return false;

    return true;
  }

  private static final Map<String,Map<String,Constraint>> roleToConstraint = new HashMap<String,Map<String,Constraint>>();

  private static Constraint getConstraint(final Map<String,Constraint> authTypeToConstraint, final String authType, final String role) {
    Constraint constraint = authTypeToConstraint.get(authType);
    if (constraint != null)
      return constraint;

    authTypeToConstraint.put(authType, constraint = new Constraint(authType, role));
    constraint.setAuthenticate(true);
    return constraint;
  }

  private static Constraint getBasicAuthConstraint(final String authType, final String role) {
    Map<String,Constraint> authTypeToConstraint = roleToConstraint.get(role);
    if (authTypeToConstraint == null)
      roleToConstraint.put(role, authTypeToConstraint = new HashMap<String,Constraint>());

    return getConstraint(authTypeToConstraint, authType, role);
  }

  private static void addServlet(final ServletContextHandler context, final Class<? extends HttpServlet> servletClass) {
    if (addedServletClasses.contains(servletClass))
      return;

    final WebServlet webServlet = servletClass.getAnnotation(WebServlet.class);
    if (webServlet == null) {
      logger.warn("HttpServlet class " + servletClass.getName() + " is missing the @WebServlet annotation");
      return;
    }

    final HttpServlet servlet;
    try {
      servlet = servletClass.getDeclaredConstructor().newInstance();
    }
    catch (final IllegalAccessException | InstantiationException | InvocationTargetException | NoSuchMethodException e) {
      logger.warn(e.getMessage());
      return;
    }

    final String[] urlPatterns = webServlet.value().length != 0 ? webServlet.value() : webServlet.urlPatterns();
    if (urlPatterns.length == 0) {
      logger.warn("HttpServlet class " + servletClass.getName() + " is missing an URL pattern on the @WebServlet annotation");
      return;
    }

    final Map<String,String> initParams = new HashMap<String,String>();
    for (final WebInitParam webInitParam : webServlet.initParams())
      initParams.put(webInitParam.name(), webInitParam.value());

    final String servletName = webServlet.name().length() > 0 ? webServlet.name() : servletClass.getName();

    final ServletSecurity servletSecurity = servletClass.getAnnotation(ServletSecurity.class);
    if (servletSecurity != null && servletSecurity.value().rolesAllowed().length > 0) {
      for (final String urlPattern : urlPatterns) {
        for (final String role : servletSecurity.value().rolesAllowed()) {
          final ConstraintMapping constraintMapping = new ConstraintMapping();
          constraintMapping.setConstraint(getBasicAuthConstraint(Constraint.__BASIC_AUTH, role));
          constraintMapping.setPathSpec(urlPattern);
          final SecurityHandler securityHandler = context.getSecurityHandler();
          if (!(securityHandler instanceof ConstraintSecurityHandler))
            throw new UnsupportedOperationException("SecurityHandler of ServletContextHandler must be a ConstraintSecurityHandler, did you call setConstraintSecurityHandler()?");

          ((ConstraintSecurityHandler)securityHandler).addConstraintMapping(constraintMapping);
        }
      }

      logger.info(servletClass.getSimpleName() + " [" + context.getSecurityHandler().getLoginService().getName() + "]: " + Arrays.toString(urlPatterns));
    }

    logger.info(servletClass.getName() + " " + Arrays.toString(urlPatterns));
    addedServletClasses.add(servletClass);
    for (final String urlPattern : urlPatterns) {
      final ServletHolder servletHolder = new ServletHolder(servlet);
      servletHolder.setName(servletName);
      servletHolder.getRegistration().setInitParameters(initParams);
      servletHolder.getRegistration().setMultipartConfig(new MultipartConfigElement(""));
      context.addServlet(servletHolder, urlPattern);
    }
  }

  private static void addFilter(final ServletContextHandler context, final Class<? extends Filter> filterClass) {
    if (addedFilterClasses.contains(filterClass))
      return;

    final WebFilter webFilter = filterClass.getAnnotation(WebFilter.class);
    if (webFilter == null) {
      logger.warn("WebFilter class " + filterClass.getName() + " is missing the @WebFilter annotation");
      return;
    }

    logger.info(filterClass.getName() + " " + Arrays.toString(webFilter.urlPatterns()));
    addedFilterClasses.add(filterClass);
    for (final String urlPattern : webFilter.urlPatterns()) {
      context.addFilter(filterClass, urlPattern, webFilter.dispatcherTypes().length > 0 ? EnumSet.of(webFilter.dispatcherTypes()[0], webFilter.dispatcherTypes()) : EnumSet.noneOf(DispatcherType.class));
    }
  }

  private static ServletContextHandler createServletContextHandler(final Realm realm) {
    final ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);

    if (realm != null) {
      final ConstraintSecurityHandler securityHandler = new ConstraintSecurityHandler();
      final HashLoginService login = new HashLoginService(realm.getName());
      final UserStore userStore = new UserStore();
      for (final Map.Entry<String,String> entry : realm.getCredentials().entrySet())
        for (final String role : realm.getRoles())
          userStore.addUser(entry.getKey(), Credential.getCredential(entry.getValue()), new String[] {role});

      login.setUserStore(userStore);
      securityHandler.setRealmName(realm.getName());
      securityHandler.setLoginService(login);
      securityHandler.setAuthenticator(new BasicAuthenticator());
      context.setSecurityHandler(securityHandler);
    }

    return context;
  }

  @SuppressWarnings("unchecked")
  private static ServletContextHandler addAllServlets(final Realm realm, final Set<Class<? extends HttpServlet>> servletClasses, final Set<Class<? extends Filter>> filterClasses) {
    final ServletContextHandler context = createServletContextHandler(realm);
    if (servletClasses != null)
      for (final Class<? extends HttpServlet> servletClass : servletClasses)
        addServlet(context, servletClass);

    // FIXME: Without the UncaughtServletExceptionFilter, errors would lead to: net::ERR_INCOMPLETE_CHUNKED_ENCODING
    addFilter(context, UncaughtServletExceptionFilter.class);
    if (filterClasses != null)
      for (final Class<? extends Filter> filterClass : filterClasses)
        addFilter(context, filterClass);

    if (servletClasses == null || filterClasses == null) {
      for (final Package pkg : Package.getPackages()) {
        if (acceptPackage(pkg)) {
          try {
            PackageLoader.getSystemContextPackageLoader().loadPackage(pkg, new Predicate<Class<?>>() {
              @Override
              public boolean test(final Class<?> t) {
                if (Modifier.isAbstract(t.getModifiers()))
                  return false;

                if (servletClasses == null && HttpServlet.class.isAssignableFrom(t))
                  addServlet(context, (Class<? extends HttpServlet>)t);
                else if (filterClasses == null && Filter.class.isAssignableFrom(t) && t.isAnnotationPresent(WebFilter.class))
                  addFilter(context, (Class<? extends Filter>)t);

                return false;
              }
            });
          }
          catch (final PackageNotFoundException e) {
            throw new RuntimeException(e);
          }
        }
      }
    }

    return context;
  }

  public static void setUncaughtServletExceptionHandler(final UncaughtServletExceptionHandler uncaughtServletExceptionHandler) {
    EmbeddedServletContainer.uncaughtServletExceptionHandler = uncaughtServletExceptionHandler;
  }

  protected static UncaughtServletExceptionHandler getUncaughtServletExceptionHandler() {
    return EmbeddedServletContainer.uncaughtServletExceptionHandler;
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
    sslContextFactory.setKeyStorePath(Thread.currentThread().getContextClassLoader().getResource(keyStorePath).toExternalForm());
    sslContextFactory.setKeyStorePassword(keyStorePassword);

    final ServerConnector connector = new ServerConnector(server, new SslConnectionFactory(sslContextFactory, "http/1.1"), new HttpConnectionFactory(https));
    connector.setPort(port);
    return connector;
  }

  private final Server server = new Server();

  public EmbeddedServletContainer(final int port, final String keyStorePath, final String keyStorePassword, final boolean externalResourcesAccess, final Realm realm, final Set<Class<? extends HttpServlet>> servletClasses, final Set<Class<? extends Filter>> filterClasses) {
    final ServletContextHandler context = addAllServlets(realm, servletClasses, filterClasses);
    server.setConnectors(new Connector[] {makeConnector(server, port, keyStorePath, keyStorePassword)});

    final HandlerCollection handlers = new HandlerCollection();
    for (final Handler handler : server.getHandlers())
      handlers.addHandler(handler);

    if (externalResourcesAccess) {
      // FIXME: HACK: Why cannot I just get the "/" resource? In the IDE it works, but in the stand-alone jar, it does not
      try {
        final String resourceName = getClass().getName().replace('.', '/') + ".class";
        final String configResourcePath = Thread.currentThread().getContextClassLoader().getResource(resourceName).toExternalForm();
        final URL rootResourceURL = new URL(configResourcePath.substring(0, configResourcePath.length() - resourceName.length()));

        final ResourceHandler resourceHandler = new ResourceHandler();
        resourceHandler.setDirectoriesListed(true);
        resourceHandler.setBaseResource(Resource.newResource(rootResourceURL));

        handlers.addHandler(resourceHandler);
      }
      catch (final IOException e) {
        throw new UnsupportedOperationException(e);
      }
    }

    handlers.addHandler(context);

    final RequestLogHandler requestLogHandler = new RequestLogHandler();
    requestLogHandler.setServer(server);
    final Slf4jRequestLog requestLog = new Slf4jRequestLog();
    requestLog.setPreferProxiedForAddress(true);
    requestLogHandler.setRequestLog(requestLog);
    handlers.addHandler(requestLogHandler);

    server.setHandler(handlers);
  }

  public void start() throws Exception {
    server.start();
  }

  @Override
  public void close() throws Exception {
    server.stop();
  }

  public void join() throws InterruptedException {
    server.join();
  }
}