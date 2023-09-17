/* Copyright (c) 2016 OpenJAX
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

import static org.libj.lang.Assertions.*;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import javax.servlet.DispatcherType;
import javax.servlet.Filter;
import javax.servlet.MultipartConfigElement;
import javax.servlet.annotation.ServletSecurity;
import javax.servlet.annotation.WebFilter;
import javax.servlet.annotation.WebInitParam;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;

import org.eclipse.jetty.alpn.server.ALPNServerConnectionFactory;
import org.eclipse.jetty.http2.server.HTTP2CServerConnectionFactory;
import org.eclipse.jetty.http2.server.HTTP2ServerConnectionFactory;
import org.eclipse.jetty.jmx.MBeanContainer;
import org.eclipse.jetty.security.ConstraintMapping;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.security.HashLoginService;
import org.eclipse.jetty.security.SecurityHandler;
import org.eclipse.jetty.security.UserStore;
import org.eclipse.jetty.security.authentication.BasicAuthenticator;
import org.eclipse.jetty.server.CustomRequestLog;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.NetworkConnector;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.Slf4jRequestLogWriter;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.server.handler.HandlerCollection;
import org.eclipse.jetty.server.handler.ResourceHandler;
import org.eclipse.jetty.server.handler.StatisticsHandler;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.resource.Resource;
import org.eclipse.jetty.util.security.Constraint;
import org.eclipse.jetty.util.security.Credential;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.libj.lang.PackageLoader;
import org.libj.lang.PackageNotFoundException;
import org.libj.net.URLs;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Simple API to initialize a Servlet Container in a JVM, significantly reducing the headache most people have when attempting to
 * accomplish the same with Jetty's raw APIs.
 */
public class EmbeddedJetty9 implements AutoCloseable {
  private static final Logger logger = LoggerFactory.getLogger(EmbeddedJetty9.class);

  private static final Set<Class<? extends HttpServlet>> addedServletClasses = new HashSet<>();
  private static final Set<Class<? extends Filter>> addedFilterClasses = new HashSet<>();
  private static final String[] excludePackageStartsWith = {"jdk", "java", "javax", "com.sun", "sun", "org.w3c", "org.xml", "org.jvnet", "org.joda", "org.jcp", "apple.security"};

  private static boolean acceptPackage(final Package pkg) {
    for (int i = 0, i$ = excludePackageStartsWith.length; i < i$; ++i) // [A]
      if (pkg.getName().startsWith(excludePackageStartsWith[i] + "."))
        return false;

    return true;
  }

  private static final Map<String,Map<String,Constraint>> roleToConstraint = new HashMap<>();

  private static Constraint getBasicAuthConstraint(final String authType, final String role) {
    Map<String,Constraint> authTypeToConstraint = roleToConstraint.get(role);
    if (authTypeToConstraint == null)
      roleToConstraint.put(role, authTypeToConstraint = new HashMap<>());

    return getConstraint(authTypeToConstraint, authType, role);
  }

  private static Constraint getConstraint(final Map<String,Constraint> authTypeToConstraint, final String authType, final String role) {
    Constraint constraint = authTypeToConstraint.get(authType);
    if (constraint != null)
      return constraint;

    authTypeToConstraint.put(authType, constraint = new Constraint(authType, role));
    constraint.setAuthenticate(true);
    return constraint;
  }

  @SuppressWarnings("null")
  private static void addServlet(final ServletContextHandler context, Class<? extends HttpServlet> servletClass, HttpServlet servletInstance) {
    if ((servletClass == null) == (servletInstance == null))
      throw new IllegalArgumentException("Either servletClass (" + servletClass + ") XOR servletInstance (" + servletInstance + ") can be provided, not neither and not both");

    if (servletClass == null)
      servletClass = servletInstance.getClass();
    else if (addedServletClasses.contains(servletClass))
      return;
    else
      addedServletClasses.add(servletClass);

    final WebServlet webServlet = servletClass.getAnnotation(WebServlet.class);
    if (webServlet == null) {
      if (logger.isWarnEnabled()) logger.warn("HttpServlet class " + servletClass.getName() + " is missing the @WebServlet annotation");
      return;
    }

    if (servletInstance == null) {
      try {
        servletInstance = servletClass.getDeclaredConstructor().newInstance();
      }
      catch (final IllegalAccessException | InstantiationException | InvocationTargetException | NoSuchMethodException e) {
        if (logger.isWarnEnabled()) logger.warn(e instanceof InvocationTargetException ? e.getCause().getMessage() : e.getMessage());
        return;
      }
    }

    final String[] urlPatterns = webServlet.value().length != 0 ? webServlet.value() : webServlet.urlPatterns();
    if (urlPatterns.length == 0) {
      if (logger.isWarnEnabled()) logger.warn("HttpServlet class " + servletClass.getName() + " is missing an URL pattern on the @WebServlet annotation");
      return;
    }

    final Map<String,String> initParams = new HashMap<>();
    for (final WebInitParam webInitParam : webServlet.initParams()) // [A]
      initParams.put(webInitParam.name(), webInitParam.value());

    final String servletName = webServlet.name().length() > 0 ? webServlet.name() : servletClass.getName();
    final ServletSecurity servletSecurity = servletClass.getAnnotation(ServletSecurity.class);
    if (servletSecurity != null && servletSecurity.value().rolesAllowed().length > 0) {
      for (final String urlPattern : urlPatterns) { // [A]
        for (final String role : servletSecurity.value().rolesAllowed()) { // [A]
          final ConstraintMapping constraintMapping = new ConstraintMapping();
          constraintMapping.setConstraint(getBasicAuthConstraint(Constraint.__BASIC_AUTH, role));
          constraintMapping.setPathSpec(urlPattern);
          final SecurityHandler securityHandler = context.getSecurityHandler();
          if (!(securityHandler instanceof ConstraintSecurityHandler))
            throw new UnsupportedOperationException("SecurityHandler of ServletContextHandler must be a ConstraintSecurityHandler, did you call setConstraintSecurityHandler()?");

          ((ConstraintSecurityHandler)securityHandler).addConstraintMapping(constraintMapping);
        }
      }

      if (logger.isInfoEnabled()) logger.info(servletClass.getSimpleName() + " [" + context.getSecurityHandler().getLoginService().getName() + "]: " + Arrays.toString(urlPatterns));
    }

    if (logger.isInfoEnabled()) logger.info(servletClass.getName() + " " + Arrays.toString(urlPatterns));
    for (final String urlPattern : urlPatterns) { // [A]
      final ServletHolder servletHolder = new ServletHolder(servletInstance);
      servletHolder.setName(servletName);
      servletHolder.getRegistration().setInitParameters(initParams);
      servletHolder.getRegistration().setMultipartConfig(new MultipartConfigElement(""));
      context.addServlet(servletHolder, urlPattern);
    }
  }

  @SuppressWarnings("null")
  private static void addFilter(final ServletContextHandler context, Class<? extends Filter> filterClass, final Filter filterInstance) {
    if ((filterClass == null) == (filterInstance == null))
      throw new IllegalArgumentException("filterClass XOR filterInstance MUST BE not null");

    if (filterClass == null)
      filterClass = filterInstance.getClass();
    else if (addedFilterClasses.contains(filterClass))
      return;
    else
      addedFilterClasses.add(filterClass);

    final WebFilter webFilter = filterClass.getAnnotation(WebFilter.class);
    if (webFilter == null) {
      if (logger.isWarnEnabled()) logger.warn("WebFilter class " + filterClass.getName() + " is missing the @WebFilter annotation");
      return;
    }

    // FIXME: Is it supposed to be EnumSet.noneOf(DispatcherType.class)??? in the addFilter call
    if (logger.isInfoEnabled()) logger.info(filterClass.getName() + " " + Arrays.toString(webFilter.urlPatterns()));
    if (filterInstance != null) {
      final Map<String,String> initParams = new HashMap<>();
      for (final WebInitParam webInitParam : webFilter.initParams()) // [A]
        initParams.put(webInitParam.name(), webInitParam.value());

      final FilterHolder filterHolder = new FilterHolder(filterInstance);
      filterHolder.setName(webFilter.filterName().length() > 0 ? webFilter.filterName() : filterClass.getName());
      filterHolder.getRegistration().setInitParameters(initParams);
      for (final String urlPattern : webFilter.urlPatterns()) { // [A]
        context.addFilter(filterHolder, urlPattern, webFilter.dispatcherTypes().length > 0 ? EnumSet.of(webFilter.dispatcherTypes()[0], webFilter.dispatcherTypes()) : EnumSet.noneOf(DispatcherType.class));
      }
    }
    else {
      for (final String urlPattern : webFilter.urlPatterns()) { // [A]
        context.addFilter(filterClass, urlPattern, webFilter.dispatcherTypes().length > 0 ? EnumSet.of(webFilter.dispatcherTypes()[0], webFilter.dispatcherTypes()) : EnumSet.noneOf(DispatcherType.class));
      }
    }
  }

  private static ServletContextHandler createServletContextHandler(final Realm realm) {
    final ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
    if (realm != null) {
      final ConstraintSecurityHandler securityHandler = new ConstraintSecurityHandler();
      final HashLoginService login = new HashLoginService(realm.getName());
      final UserStore userStore = new UserStore();
      final Map<String,String> credentials = realm.getCredentials();
      if (credentials.size() > 0)
        for (final Map.Entry<String,String> entry : credentials.entrySet()) { // [S]
          final Set<String> roles = realm.getRoles();
          if (roles.size() > 0)
            for (final String role : roles) // [S]
              userStore.addUser(entry.getKey(), Credential.getCredential(entry.getValue()), new String[] {role});
        }

      login.setUserStore(userStore);
      securityHandler.setRealmName(realm.getName());
      securityHandler.setLoginService(login);
      securityHandler.setAuthenticator(new BasicAuthenticator());
      context.setSecurityHandler(securityHandler);
    }

    return context;
  }

  @SuppressWarnings("unchecked")
  private static void addAllServlets(final ServletContextHandler context, final UncaughtServletExceptionHandler uncaughtServletExceptionHandler, final Set<Class<? extends HttpServlet>> servletClasses, final Set<? extends HttpServlet> servletInstances, final Set<Class<? extends Filter>> filterClasses, final Set<? extends Filter> filterInstances) {
    if (servletClasses != null && servletClasses.size() > 0)
      for (final Class<? extends HttpServlet> servletClass : servletClasses) // [S]
        addServlet(context, servletClass, null);

    if (servletInstances != null && servletInstances.size() > 0)
      for (final HttpServlet servletInstance : servletInstances) // [S]
        addServlet(context, null, servletInstance);

    if (uncaughtServletExceptionHandler != null)
      addFilter(context, null, new UncaughtServletExceptionFilter(uncaughtServletExceptionHandler));

    if (filterClasses != null && filterClasses.size() > 0)
      for (final Class<? extends Filter> filterClass : filterClasses) // [S]
        addFilter(context, filterClass, null);

    if (filterInstances != null && filterInstances.size() > 0)
      for (final Filter filterInstance : filterInstances) // [S]
        addFilter(context, null, filterInstance);

    final boolean scanServlets = servletClasses == null && servletInstances == null;
    final boolean scanFilters = filterClasses == null && filterInstances == null;
    if (scanServlets || scanFilters) {
      for (final Package pkg : Package.getPackages()) { // [A]
        if (acceptPackage(pkg)) {
          try {
            PackageLoader.getContextPackageLoader().loadPackage(pkg, t -> {
              if (Modifier.isAbstract(t.getModifiers()))
                return false;

              if (scanServlets && HttpServlet.class.isAssignableFrom(t))
                addServlet(context, (Class<? extends HttpServlet>)t, null);
              else if (scanFilters && Filter.class.isAssignableFrom(t) && t.isAnnotationPresent(WebFilter.class))
                addFilter(context, (Class<? extends Filter>)t, null);

              return false;
            });
          }
          catch (final IOException | PackageNotFoundException e) {
            throw new IllegalStateException(e);
          }
        }
      }
    }
  }

  // FIXME: Allow both http and https connectors to coexist

  @SuppressWarnings("resource")
  private static void addConnectors(final Server server, final int port, final boolean http2, final long idleTimeout, final String keyStorePath, final String keyStorePassword) {
    server.addBean(new MBeanContainer(ManagementFactory.getPlatformMBeanServer()));

    final HttpConfiguration httpConfig = new HttpConfiguration();

    final ServerConnector httpConnector, httpsConnector;
    if (http2) {
      httpConnector = new ServerConnector(server, new HttpConnectionFactory(httpConfig), new HTTP2CServerConnectionFactory(httpConfig));
    }
    else {
      httpConnector = new ServerConnector(server, new HttpConnectionFactory(httpConfig));
    }

    httpConnector.setIdleTimeout(idleTimeout);

    if (keyStorePath == null || keyStorePassword == null) {
      httpConnector.setPort(port);
      server.setConnectors(new ServerConnector[] { httpConnector });
      return;
    }

    final HttpConfiguration httpsConfig = new HttpConfiguration(httpConfig);
    httpsConfig.addCustomizer(new SecureRequestCustomizer());

    final SslContextFactory sslContextFactory = new SslContextFactory.Server();
    httpsConfig.addCustomizer(new SecureRequestCustomizer());

    final URL resource = assertNotNull(Thread.currentThread().getContextClassLoader().getResource(keyStorePath), () -> "KeyStore path not found: " + keyStorePath);
    sslContextFactory.setKeyStorePath(resource.toString());
    sslContextFactory.setKeyStorePassword(keyStorePassword);

    final ALPNServerConnectionFactory alpnConnectionFactory = new ALPNServerConnectionFactory(httpConnector.getDefaultProtocol());
    final HttpConnectionFactory httpConnectionFactory = new HttpConnectionFactory(httpsConfig);
    final SslConnectionFactory sslConnectionFactory = new SslConnectionFactory(sslContextFactory, alpnConnectionFactory.getProtocol());

    if (http2) {
      httpsConnector = new ServerConnector(server, sslConnectionFactory, alpnConnectionFactory, new HTTP2ServerConnectionFactory(httpsConfig), httpConnectionFactory);
    }
    else {
      // Here alpnConnectionFactory.getProtocol() should be "http/1.1"
      httpsConnector = new ServerConnector(server, sslConnectionFactory, alpnConnectionFactory, httpConnectionFactory);
    }

    httpsConnector.setIdleTimeout(idleTimeout);

    httpsConnector.setPort(port);
    server.setConnectors(new ServerConnector[] { httpsConnector });
  }

  private static final int DEFAULT_PORT = 0;
  private static final String DEFAULT_CONTEXT_PATH = "/";
  private static final boolean DEFAULT_EXTERNAL_RESOURCE_ACCESS = false;
  private static final boolean DEFAULT_HTTP2 = true;
  private static final boolean DEFAULT_STOP_AT_SHUTDOWN = false;
  private static final long DEFAULT_SHUTDOWN_TIMEOUT = 30000;
  private static final long DEFAULT_IDLE_TIMEOUT = 0;

  public static class Builder {
    private int port = DEFAULT_PORT;

    /**
     * Returns the builder instance.
     *
     * @param port The listen port, which must be between 0 and 65535. A value of 0 advises Jetty to set a random port that is
     *          available. The port can thereafter be determined with {@link #getPort()}. Default: 0.
     * @return The builder instance.
     * @throws IllegalArgumentException If port is not between 0 and 65535.
     */
    public Builder withPort(final int port) {
      if (port < 0 || 65535 < port)
        throw new IllegalArgumentException("Port (" + port + ") must be between 0 and 65535");

      this.port = port;
      return this;
    }

    private String contextPath = DEFAULT_CONTEXT_PATH;

    /**
     * Returns the builder instance.
     *
     * @param contextPath The prefix portion of request URIs to be matched for handling by the container. If the provided
     *          {@code contextPath} does not start with {@code "/"}, one will be prepended. If the provided {@code contextPath} ends
     *          with {@code "/*"} or {@code "/"}, this will be removed. Default: "/".
     * @return The builder instance.
     * @throws NullPointerException If {@code contextPath} is null.
     */
    public Builder withContextPath(final String contextPath) {
      Objects.requireNonNull(contextPath, "contextPath is null");

      this.contextPath = contextPath;
      return this;
    }

    private String keyStorePath;
    private String keyStorePassword;

    /**
     * Returns the builder instance.
     *
     * @param keyStorePath The path of the SSL keystore.
     * @param keyStorePassword The password for the key store.
     * @return The builder instance.
     */
    public Builder withKeyStore(final String keyStorePath, final String keyStorePassword) {
      this.keyStorePath = keyStorePath;
      this.keyStorePassword = keyStorePassword;
      return this;
    }

    private boolean externalResourcesAccess = DEFAULT_EXTERNAL_RESOURCE_ACCESS;

    /**
     * Returns the builder instance. Default: false.
     *
     * @param externalResourcesAccess Whether the server should provide directory listings for its resources.
     * @return The builder instance.
     */
    public Builder withExternalResourcesAccess(final boolean externalResourcesAccess) {
      this.externalResourcesAccess = externalResourcesAccess;
      return this;
    }

    private boolean http2 = DEFAULT_HTTP2;

    /**
     * Returns the builder instance.
     *
     * @param http2 Whether the server should support HTTP/2. Default: true.
     * @return The builder instance.
     */
    public Builder withHttp2(final boolean http2) {
      this.http2 = http2;
      return this;
    }

    private boolean stopAtShutdown = DEFAULT_STOP_AT_SHUTDOWN;

    /**
     * Returns the builder instance.
     *
     * @param stopAtShutdown Whether the container should be explicitly stopped (and thus fulfill its graceful shutdown) when the
     *          JVM is shutdown. Default: false.
     * @return The builder instance.
     */
    public Builder withStopAtShutdown(final boolean stopAtShutdown) {
      this.stopAtShutdown = stopAtShutdown;
      return this;
    }

    private long shutdownTimeout = DEFAULT_SHUTDOWN_TIMEOUT;

    /**
     * Returns the builder instance.
     *
     * @param shutdownTimeout The timeout (in milliseconds) for the server to gracefully stop before exiting.
     * @return The builder instance.
     * @throws IllegalArgumentException If {@code shutdownTimeout} is negative.
     */
    public Builder withShutdownTimeout(final long shutdownTimeout) {
      this.shutdownTimeout = assertNotNegative(shutdownTimeout);
      return this;
    }

    private long idleTimeout = DEFAULT_IDLE_TIMEOUT;

    /**
     * Returns the builder instance.
     *
     * @param idleTimeout The maximum idle time for a connection.
     * @return The builder instance.
     * @throws IllegalArgumentException If {@code idleTimeout} is negative.
     * @see ServerConnector#setIdleTimeout(long)
     */
    public Builder withIdleTimeout(final long idleTimeout) {
      this.idleTimeout = assertNotNegative(idleTimeout);
      return this;
    }

    private Realm realm;

    /**
     * Returns the builder instance.
     *
     * @param realm The realm of roles and credentials.
     * @return The builder instance.
     */
    public Builder withRealm(final Realm realm) {
      this.realm = realm;
      return this;
    }

    private UncaughtServletExceptionHandler uncaughtServletExceptionHandler;

    /**
     * Returns the builder instance.
     *
     * @param uncaughtServletExceptionHandler Handler to be used for uncaught servlet exceptions.
     * @return The builder instance.
     */
    public Builder withUncaughtServletExceptionHandler(final UncaughtServletExceptionHandler uncaughtServletExceptionHandler) {
      this.uncaughtServletExceptionHandler = uncaughtServletExceptionHandler;
      return this;
    }

    private Set<Class<? extends HttpServlet>> servletClasses;

    /**
     * Returns the builder instance.
     *
     * @param servletClasses Set of servlet classes to be registered with Jetty's web context. If the specified set is null, and the
     *          {@code servletInstances} set is null, the {@link EmbeddedJetty9} will scan candidate packages for
     *          {@link HttpServlet} classes to load automatically.
     * @return The builder instance.
     */
    public Builder withServletClasses(final Set<Class<? extends HttpServlet>> servletClasses) {
      this.servletClasses = servletClasses;
      return this;
    }

    /**
     * Returns the builder instance.
     *
     * @param servletClasses Array of servlet classes to be registered with Jetty's web context. If the specified array is null, and
     *          the {@code servletInstances} set is null, the {@link EmbeddedJetty9} will scan candidate packages for
     *          {@link HttpServlet} classes to load automatically.
     * @return The builder instance.
     */
    @SafeVarargs
    public final Builder withServletClasses(final Class<? extends HttpServlet> ... servletClasses) {
      if (servletClasses != null) {
        this.servletClasses = new HashSet<>(servletClasses.length);
        Collections.addAll(this.servletClasses, servletClasses);
      }
      else {
        this.servletClasses = null;
      }

      return this;
    }

    private Set<HttpServlet> servletInstances;

    /**
     * Returns the builder instance.
     *
     * @param servletInstances Set of servlet instances to be registered with Jetty's web context. If the specified set is null, and
     *          the {@code servletInstances} set is null, the {@link EmbeddedJetty9} will scan candidate packages for
     *          {@link HttpServlet} classes to load automatically.
     * @return The builder instance.
     */
    public Builder withServletInstances(final Set<HttpServlet> servletInstances) {
      this.servletInstances = servletInstances;
      return this;
    }

    /**
     * Returns the builder instance.
     *
     * @param servletInstances Array of servlet instances to be registered with Jetty's web context. If the specified array is null,
     *          and the {@code servletInstances} set is null, the {@link EmbeddedJetty9} will scan candidate packages for
     *          {@link HttpServlet} classes to load automatically.
     * @return The builder instance.
     */
    public Builder withServletInstances(final HttpServlet ... servletInstances) {
      if (servletInstances != null) {
        this.servletInstances = new HashSet<>(servletInstances.length);
        Collections.addAll(this.servletInstances, servletInstances);
      }
      else {
        this.servletInstances = null;
      }

      return this;
    }

    private Set<Class<? extends Filter>> filterClasses;

    /**
     * Returns the builder instance.
     *
     * @param filterClasses Set of filter classes to be registered with Jetty's web context. If the specified set is null, and the
     *          {@code filterInstances} set is null, the {@link EmbeddedJetty9} will scan candidate packages for
     *          {@link Filter} classes to load automatically.
     * @return The builder instance.
     */
    public Builder withFilterClasses(final Set<Class<? extends Filter>> filterClasses) {
      this.filterClasses = filterClasses;
      return this;
    }

    /**
     * Returns the builder instance.
     *
     * @param filterClasses Array of filter classes to be registered with Jetty's web context. If the specified array is null, and
     *          the {@code filterInstances} set is null, the {@link EmbeddedJetty9} will scan candidate packages for
     *          {@link Filter} classes to load automatically.
     * @return The builder instance.
     */
    @SafeVarargs
    public final Builder withFilterClasses(final Class<? extends Filter> ... filterClasses) {
      if (filterClasses != null) {
        this.filterClasses = new HashSet<>(filterClasses.length);
        Collections.addAll(this.filterClasses, filterClasses);
      }
      else {
        this.filterClasses = null;
      }

      return this;
    }

    private Set<Filter> filterInstances;

    /**
     * Returns the builder instance.
     *
     * @param filterInstances Set of filter instances to be registered with Jetty's web context. If the specified set is null, and
     *          the {@code filterInstances} set is null, the {@link EmbeddedJetty9} will scan candidate packages for
     *          {@link Filter} classes to load automatically.
     * @return The builder instance.
     */
    public Builder withFilterInstances(final Set<Filter> filterInstances) {
      this.filterInstances = filterInstances;
      return this;
    }

    /**
     * Returns the builder instance.
     *
     * @param filterInstances Array of filter instances to be registered with Jetty's web context. If the specified array is null,
     *          and the {@code filterInstances} set is null, the {@link EmbeddedJetty9} will scan candidate packages for
     *          {@link Filter} classes to load automatically.
     * @return The builder instance.
     */
    public Builder withFilterInstances(final Filter ... filterInstances) {
      if (filterInstances != null) {
        this.filterInstances = new HashSet<>(filterInstances.length);
        Collections.addAll(this.filterInstances, filterInstances);
      }
      else {
        this.filterInstances = null;
      }

      return this;
    }

    /**
     * Returns a new {@link EmbeddedJetty9} with the configuration in this builder instance.
     *
     * @return A new {@link EmbeddedJetty9} with the configuration in this builder instance.
     */
    public EmbeddedJetty9 build() {
      return new EmbeddedJetty9(port, contextPath, keyStorePath, keyStorePassword, externalResourcesAccess, http2, stopAtShutdown, shutdownTimeout, idleTimeout, realm, uncaughtServletExceptionHandler, servletClasses, servletInstances, filterClasses, filterInstances);
    }
  }

  private final Server server;

  /**
   * Creates a new {@link EmbeddedJetty9} with the specified port. The {@link EmbeddedJetty9} will scan all
   * classes of the context class loader to automatically locate servlet and filter classes.
   *
   * @param port The listen port, which must be between 0 and 65535. A value of 0 advises Jetty to set a random port that is
   *          available. The port can thereafter be determined with {@link #getPort()}.
   * @param uncaughtServletExceptionHandler Handler to be used for uncaught servlet exceptions.
   * @throws IllegalArgumentException If port is not between 0 and 65535.
   */
  public EmbeddedJetty9(final int port, final UncaughtServletExceptionHandler uncaughtServletExceptionHandler) {
    this(port, DEFAULT_CONTEXT_PATH, null, null, DEFAULT_EXTERNAL_RESOURCE_ACCESS, DEFAULT_HTTP2, DEFAULT_STOP_AT_SHUTDOWN, DEFAULT_SHUTDOWN_TIMEOUT, DEFAULT_IDLE_TIMEOUT, null, uncaughtServletExceptionHandler, null, null, null, null);
  }

  /**
   * Creates a new {@link EmbeddedJetty9} with the specified port, and servlet and filter classes to be registered with
   * Jetty's web context.
   *
   * @param port The listen port, which must be between 0 and 65535. A value of 0 advises Jetty to set a random port that is
   *          available. The port can thereafter be determined with {@link #getPort()}.
   * @param uncaughtServletExceptionHandler Handler to be used for uncaught servlet exceptions.
   * @param servletClasses Set of servlet classes to be registered with Jetty's web context. If the specified set is null, and the
   *          {@code servletInstances} set is null, the {@link EmbeddedJetty9} will scan candidate packages for
   *          {@link HttpServlet} classes to load automatically.
   * @param servletInstances Set of servlet instances to be registered with Jetty's web context. If the specified set is null, and
   *          the {@code servletInstances} set is null, the {@link EmbeddedJetty9} will scan candidate packages for
   *          {@link HttpServlet} classes to load automatically.
   * @param filterClasses Set of filter classes to be registered with Jetty's web context. If the specified set is null, and the
   *          {@code filterInstances} set is null, the {@link EmbeddedJetty9} will scan candidate packages for
   *          {@link Filter} classes to load automatically.
   * @param filterInstances Set of filter instances to be registered with Jetty's web context. If the specified set is null, and the
   *          {@code filterInstances} set is null, the {@link EmbeddedJetty9} will scan candidate packages for
   *          {@link Filter} classes to load automatically.
   * @throws IllegalArgumentException If port is not between 0 and 65535.
   */
  public EmbeddedJetty9(final int port, final UncaughtServletExceptionHandler uncaughtServletExceptionHandler, final Set<Class<? extends HttpServlet>> servletClasses, final Set<HttpServlet> servletInstances, final Set<Class<? extends Filter>> filterClasses, final Set<Filter> filterInstances) {
    this(port, DEFAULT_CONTEXT_PATH, null, null, DEFAULT_EXTERNAL_RESOURCE_ACCESS, DEFAULT_HTTP2, DEFAULT_STOP_AT_SHUTDOWN, DEFAULT_SHUTDOWN_TIMEOUT, DEFAULT_IDLE_TIMEOUT, null, uncaughtServletExceptionHandler, servletClasses, servletInstances, filterClasses, filterInstances);
  }

  /**
   * Creates a new {@link EmbeddedJetty9} with the specified port, and servlet and filter classes to be registered with
   * Jetty's web context.
   *
   * @param port The listen port, which must be between 0 and 65535. A value of 0 advises Jetty to set a random port that is
   *          available. The port can thereafter be determined with {@link #getPort()}.
   * @param contextPath The prefix portion of request URIs to be matched for handling by the container. If the provided
   *          {@code contextPath} does not start with {@code "/"}, one will be prepended. If the provided {@code contextPath} ends
   *          with {@code "/*"} or {@code "/"}, this will be removed.
   * @param keyStorePath The path of the SSL keystore.
   * @param keyStorePassword The password for the key store.
   * @param externalResourcesAccess Whether the server should provide directory listings for its resources.
   * @param http2 Whether the server should support HTTP/2.
   * @param stopAtShutdown Whether the container should be explicitly stopped (and thus fulfill its graceful shutdown) when the JVM
   *          is shutdown.
   * @param shutdownTimeout The timeout (in milliseconds) for the server to gracefully stop before exiting.
   * @param idleTimeout The maximum idle time for a connection. See {@link ServerConnector#setIdleTimeout(long)}.
   * @param realm The realm of roles and credentials.
   * @param uncaughtServletExceptionHandler Handler to be used for uncaught servlet exceptions.
   * @param servletClasses Set of servlet classes to be registered with Jetty's web context. If the specified set is null, and the
   *          {@code servletInstances} set is null, the {@link EmbeddedJetty9} will scan candidate packages for
   *          {@link HttpServlet} classes to load automatically.
   * @param servletInstances Set of servlet instances to be registered with Jetty's web context. If the specified set is null, and
   *          the {@code servletInstances} set is null, the {@link EmbeddedJetty9} will scan candidate packages for
   *          {@link HttpServlet} classes to load automatically.
   * @param filterClasses Set of filter classes to be registered with Jetty's web context. If the specified set is null, and the
   *          {@code filterInstances} set is null, the {@link EmbeddedJetty9} will scan candidate packages for
   *          {@link Filter} classes to load automatically.
   * @param filterInstances Set of filter instances to be registered with Jetty's web context. If the specified set is null, and the
   *          {@code filterInstances} set is null, the {@link EmbeddedJetty9} will scan candidate packages for
   *          {@link Filter} classes to load automatically.
   * @throws IllegalArgumentException If port is not between 0 and 65535, or if {@code contextPath} is null.
   */
  public EmbeddedJetty9(
    final int port,
    final String contextPath,
    final String keyStorePath,
    final String keyStorePassword,
    final boolean externalResourcesAccess,
    final boolean http2,
    final boolean stopAtShutdown,
    final long shutdownTimeout,
    final long idleTimeout,
    final Realm realm,
    final UncaughtServletExceptionHandler uncaughtServletExceptionHandler,
    final Set<Class<? extends HttpServlet>> servletClasses,
    final Set<HttpServlet> servletInstances,
    final Set<Class<? extends Filter>> filterClasses,
    final Set<Filter> filterInstances) {

    if (port < 0 || 65535 < port)
      throw new IllegalArgumentException("Port (" + port + ") must be between 0 and 65535");

    this.server = new Server();

    final HandlerCollection handlers = new HandlerCollection();

    if (externalResourcesAccess) {
      final String resourceName = getClass().getName().replace('.', '/').concat(".class");
      final URL resource = getClass().getClassLoader().getResource(resourceName);

      final String configResourcePath = resource.toString();
      final URL rootResourceURL = URLs.create(configResourcePath.substring(0, configResourcePath.length() - resourceName.length()));

      final ResourceHandler resourceHandler = new ResourceHandler();
      resourceHandler.setDirectoriesListed(true);
      resourceHandler.setBaseResource(Resource.newResource(rootResourceURL));

      handlers.addHandler(resourceHandler);
    }

    final ServletContextHandler contextHandler = createServletContextHandler(realm);
    contextHandler.setContextPath(contextPath);
    addAllServlets(contextHandler, uncaughtServletExceptionHandler, servletClasses, servletInstances, filterClasses, filterInstances);
    addConnectors(server, port, http2, idleTimeout, keyStorePath, keyStorePassword);
    handlers.addHandler(contextHandler);

    server.setHandler(handlers);

    server.setStopTimeout(shutdownTimeout);
    if (stopAtShutdown) {
      server.setStopAtShutdown(true);

      final StatisticsHandler statisticsHandler = new StatisticsHandler();
      statisticsHandler.setHandler(server.getHandler());
      server.setHandler(statisticsHandler);
    }

    // Look at the javadoc for CustomRequestLog. There is no special case handling of "proxiedForAddress",
    // which relies on ForwardRequestCustomizer. For Log Latency, see "%D" formatting option.
    final CustomRequestLog requestLog = new CustomRequestLog(new Slf4jRequestLogWriter(), CustomRequestLog.EXTENDED_NCSA_FORMAT);
    server.setRequestLog(requestLog);
  }

  /**
   * Creates a new {@link EmbeddedJetty9} from the specified {@link Builder}.
   *
   * @param builder The {@link Builder}.
   */
  public EmbeddedJetty9(final EmbeddedJetty9.Builder builder) {
    this(builder.port, builder.contextPath, builder.keyStorePath, builder.keyStorePassword, builder.externalResourcesAccess, builder.http2, builder.stopAtShutdown, builder.shutdownTimeout, builder.idleTimeout, builder.realm, builder.uncaughtServletExceptionHandler, builder.servletClasses, builder.servletInstances, builder.filterClasses, builder.filterInstances);
  }

  /**
   * Starts the container.
   *
   * @throws Exception If a component fails to start.
   */
  public void start() throws Exception {
    if (!server.isStarting() && !server.isStarted())
      server.start();
  }

  /**
   * Stops the container. The container may wait for current activities to complete normally, but it can be interrupted.
   * <p>
   * {@inheritDoc}
   *
   * @throws Exception If a component fails to stop.
   */
  @Override
  public void close() throws Exception {
    if (!server.isStopping() && !server.isStopped())
      server.stop();
  }

  /**
   * Blocks until the thread of the server is stopped.
   *
   * @throws InterruptedException If thread was interrupted.
   */
  public void join() throws InterruptedException {
    server.join();
  }

  private int port;

  /**
   * Returns the actual port the connector is listening on, or -1 if it has not been opened, or -2 if it has been closed.
   *
   * @return The actual port the connector is listening on, or -1 if it has not been opened, or -2 if it has been closed.
   */
  public int getPort() {
    if (port > 0)
      return port;

    final NetworkConnector networkConnector = (NetworkConnector)server.getConnectors()[0];
    return port = networkConnector.getLocalPort();
  }
}