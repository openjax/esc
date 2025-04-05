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
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import javax.servlet.DispatcherType;
import javax.servlet.Filter;
import javax.servlet.MultipartConfigElement;
import javax.servlet.ServletRegistration.Dynamic;
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
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.NetworkConnector;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.Slf4jRequestLog;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.server.handler.HandlerCollection;
import org.eclipse.jetty.server.handler.ResourceHandler;
import org.eclipse.jetty.server.handler.StatisticsHandler;
import org.eclipse.jetty.server.handler.gzip.GzipHandler;
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
  private static final String[] excludePackagePrefixes = {"jdk.", "java.", "javax.", "com.sun.", "sun.", "org.w3c.", "org.xml.", "org.jvnet.", "org.joda.", "org.jcp.", "apple.security."};

  private static boolean acceptPackage(final Package pkg) {
    final String name = pkg.getName();
    for (final String excludePackagePrefix : excludePackagePrefixes) // [A]
      if (name.startsWith(excludePackagePrefix))
        return false;

    return true;
  }

  private static final HashMap<String,HashMap<String,Constraint>> roleToConstraint = new HashMap<>();

  private static Constraint getBasicAuthConstraint(final String authType, final String role) {
    HashMap<String,Constraint> authTypeToConstraint = roleToConstraint.get(role);
    if (authTypeToConstraint == null)
      roleToConstraint.put(role, authTypeToConstraint = new HashMap<>());

    return getConstraint(authTypeToConstraint, authType, role);
  }

  private static Constraint getConstraint(final HashMap<String,Constraint> authTypeToConstraint, final String authType, final String role) {
    Constraint constraint = authTypeToConstraint.get(authType);
    if (constraint != null)
      return constraint;

    authTypeToConstraint.put(authType, constraint = new Constraint(authType, role));
    constraint.setAuthenticate(true);
    return constraint;
  }

  private static HashMap<String,String> toMap(final WebInitParam[] initParams) {
    if (initParams == null)
      return null;

    final HashMap<String,String> map = new HashMap<>(initParams.length);
    for (final WebInitParam webInitParam : initParams) // [A]
      map.put(webInitParam.name(), webInitParam.value());

    return map;
  }

  @SuppressWarnings("null")
  private static void addServlet(final ServletContextHandler context, Class<? extends HttpServlet> servletClass, HttpServlet servletInstance, final WebServlet webServlet) {
    if ((servletClass == null) == (servletInstance == null))
      throw new IllegalArgumentException("Either servletClass (" + servletClass + ") XOR servletInstance (" + servletInstance + ") can be provided, not neither and not both");

    if (servletClass == null)
      servletClass = servletInstance.getClass();
    else if (addedServletClasses.contains(servletClass))
      return;
    else
      addedServletClasses.add(servletClass);

    if (servletInstance == null) {
      try {
        servletInstance = servletClass.getDeclaredConstructor().newInstance();
      }
      catch (final IllegalAccessException | InstantiationException | InvocationTargetException | NoSuchMethodException e) {
        if (logger.isWarnEnabled()) { logger.warn(e instanceof InvocationTargetException ? e.getCause().getMessage() : e.getMessage()); }
        return;
      }
    }

    final HashMap<String,String> initParams = toMap(webServlet.initParams());

    final String name = webServlet.name();
    final String servletName = name.length() > 0 ? name : servletClass.getName();
    final String[] urlPatterns = webServlet.urlPatterns();
    final ServletSecurity servletSecurity = servletClass.getAnnotation(ServletSecurity.class);
    final String[] rolesAllowed;
    if (servletSecurity != null && (rolesAllowed = servletSecurity.value().rolesAllowed()).length > 0) {
      for (final String urlPattern : urlPatterns) { // [A]
        for (final String role : rolesAllowed) { // [A]
          final ConstraintMapping constraintMapping = new ConstraintMapping();
          constraintMapping.setConstraint(getBasicAuthConstraint(Constraint.__BASIC_AUTH, role));
          constraintMapping.setPathSpec(urlPattern);
          final SecurityHandler securityHandler = context.getSecurityHandler();
          if (!(securityHandler instanceof ConstraintSecurityHandler))
            throw new UnsupportedOperationException("SecurityHandler of ServletContextHandler must be a ConstraintSecurityHandler, did you call setConstraintSecurityHandler()?");

          ((ConstraintSecurityHandler)securityHandler).addConstraintMapping(constraintMapping);
        }
      }

      if (logger.isInfoEnabled()) { logger.info(servletClass.getSimpleName() + " [" + context.getSecurityHandler().getLoginService().getName() + "]: " + Arrays.toString(urlPatterns)); }
    }

    if (logger.isInfoEnabled()) { logger.info(servletClass.getName() + " " + Arrays.toString(urlPatterns)); }
    for (final String urlPattern : urlPatterns) { // [A]
      final ServletHolder servletHolder = new ServletHolder(servletInstance);
      servletHolder.setName(servletName);
      final Dynamic registration = servletHolder.getRegistration();
      if (initParams != null)
        registration.setInitParameters(initParams);

      registration.setMultipartConfig(new MultipartConfigElement(""));
      context.addServlet(servletHolder, urlPattern);
    }
  }

  @SuppressWarnings("null")
  private static void addFilter(final ServletContextHandler context, Class<? extends Filter> filterClass, final Filter filterInstance, final WebFilter webFilter) {
    if ((filterClass == null) == (filterInstance == null))
      throw new IllegalArgumentException("filterClass XOR filterInstance MUST BE not null");

    if (filterClass == null)
      filterClass = filterInstance.getClass();
    else if (addedFilterClasses.contains(filterClass))
      return;
    else
      addedFilterClasses.add(filterClass);

    // FIXME: Is it supposed to be EnumSet.noneOf(DispatcherType.class)??? in the addFilter call
    if (logger.isInfoEnabled()) { logger.info(filterClass.getName() + " " + Arrays.toString(webFilter.urlPatterns())); }

    final DispatcherType[] dispatcherTypes = webFilter.dispatcherTypes();
    if (filterInstance != null) {
      final FilterHolder filterHolder = new FilterHolder(filterInstance);
      final String filterName = webFilter.filterName();
      filterHolder.setName(filterName.length() > 0 ? filterName : filterClass.getName());
      final HashMap<String,String> initParams = toMap(webFilter.initParams());
      if (initParams != null)
        filterHolder.getRegistration().setInitParameters(initParams);

      for (final String urlPattern : webFilter.urlPatterns()) { // [A]
        context.addFilter(filterHolder, urlPattern, dispatcherTypes.length > 0 ? EnumSet.of(dispatcherTypes[0], dispatcherTypes) : EnumSet.noneOf(DispatcherType.class));
      }
    }
    else {
      for (final String urlPattern : webFilter.urlPatterns()) { // [A]
        context.addFilter(filterClass, urlPattern, dispatcherTypes.length > 0 ? EnumSet.of(dispatcherTypes[0], dispatcherTypes) : EnumSet.noneOf(DispatcherType.class));
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
      if (credentials.size() > 0) {
        for (final Map.Entry<String,String> entry : credentials.entrySet()) { // [S]
          final Set<String> roles = realm.getRoles();
          if (roles.size() > 0)
            for (final String role : roles) // [S]
              userStore.addUser(entry.getKey(), Credential.getCredential(entry.getValue()), new String[] {role});
        }
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
  private static void addAllServlets(final ServletContextHandler context, final UncaughtServletExceptionHandler uncaughtServletExceptionHandler, final Map<Class<? extends HttpServlet>,WebServlet> servletClassToUrlPatterns, final Map<? extends HttpServlet,WebServlet> servletInstanceToUrlPatterns, final Map<Class<? extends Filter>,WebFilter> filterClassToUrlPatterns, final Map<? extends Filter,WebFilter> filterInstancesToUrlPatterns) {
    if (servletClassToUrlPatterns != null && servletClassToUrlPatterns.size() > 0)
      for (final Map.Entry<Class<? extends HttpServlet>,WebServlet> servletClassToUrlPattern : servletClassToUrlPatterns.entrySet()) // [S]
        addServlet(context, servletClassToUrlPattern.getKey(), null, servletClassToUrlPattern.getValue());

    if (servletInstanceToUrlPatterns != null && servletInstanceToUrlPatterns.size() > 0)
      for (final Map.Entry<? extends HttpServlet,WebServlet> servletInstanceToUrlPattern : servletInstanceToUrlPatterns.entrySet()) // [S]
        addServlet(context, null, servletInstanceToUrlPattern.getKey(), servletInstanceToUrlPattern.getValue());

    if (uncaughtServletExceptionHandler != null)
      addFilter(context, null, new UncaughtServletExceptionFilter(uncaughtServletExceptionHandler), UncaughtServletExceptionFilter.class.getAnnotation(WebFilter.class));

    if (filterClassToUrlPatterns != null && filterClassToUrlPatterns.size() > 0)
      for (final Map.Entry<Class<? extends Filter>,WebFilter> filterClassToUrlPattern : filterClassToUrlPatterns.entrySet()) // [S]
        addFilter(context, filterClassToUrlPattern.getKey(), null, filterClassToUrlPattern.getValue());

    if (filterInstancesToUrlPatterns != null && filterInstancesToUrlPatterns.size() > 0)
      for (final Map.Entry<? extends Filter,WebFilter> filterInstancesToUrlPattern : filterInstancesToUrlPatterns.entrySet()) // [S]
        addFilter(context, null, filterInstancesToUrlPattern.getKey(), filterInstancesToUrlPattern.getValue());

    final boolean scanServlets = servletClassToUrlPatterns == null && servletInstanceToUrlPatterns == null;
    final boolean scanFilters = filterClassToUrlPatterns == null && filterInstancesToUrlPatterns == null;
    if (scanServlets || scanFilters) {
      for (final Package pkg : Package.getPackages()) { // [A]
        if (acceptPackage(pkg)) {
          try {
            PackageLoader.getContextPackageLoader().loadPackage(pkg, (final Class<?> c) -> {
              if (Modifier.isAbstract(c.getModifiers()))
                return false;

              if (scanServlets && HttpServlet.class.isAssignableFrom(c))
                addServlet(context, (Class<? extends HttpServlet>)c, null, null);
              else if (scanFilters && Filter.class.isAssignableFrom(c) && c.isAnnotationPresent(WebFilter.class))
                addFilter(context, (Class<? extends Filter>)c, null, null);

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
  private static void addConnectors(final Server server, final int port, final boolean http2, final long idleTimeoutMs, final String keyStorePath, final String keyStorePassword) {
    server.addBean(new MBeanContainer(ManagementFactory.getPlatformMBeanServer()));

    final HttpConfiguration httpConfig = new HttpConfiguration();

    final ServerConnector httpConnector, httpsConnector;
    if (http2)
      httpConnector = new ServerConnector(server, new HttpConnectionFactory(httpConfig), new HTTP2CServerConnectionFactory(httpConfig));
    else
      httpConnector = new ServerConnector(server, new HttpConnectionFactory(httpConfig));

    httpConnector.setIdleTimeout(idleTimeoutMs);

    if (keyStorePath == null || keyStorePassword == null) {
      httpConnector.setPort(port);
      server.setConnectors(new ServerConnector[] {httpConnector});
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

    httpsConnector.setIdleTimeout(idleTimeoutMs);

    httpsConnector.setPort(port);
    server.setConnectors(new ServerConnector[] {httpsConnector});
  }

  private static final int DEFAULT_PORT = 0;
  private static final String DEFAULT_CONTEXT_PATH = "/";
  private static final boolean DEFAULT_EXTERNAL_RESOURCE_ACCESS = false;
  private static final boolean DEFAULT_HTTP2 = true;
  private static final boolean DEFAULT_GZIP_HANDLER = false;
  private static final boolean DEFAULT_STOP_AT_SHUTDOWN = false;
  private static final long DEFAULT_SHUTDOWN_TIMEOUT_MS = 30000;
  private static final long DEFAULT_IDLE_TIMEOUT_MS = 0;

  public static class Builder {
    private int port = DEFAULT_PORT;

    private LinkedHashMap<HttpServlet,WebServlet> servletInstances;
    private LinkedHashMap<Class<? extends HttpServlet>,WebServlet> servletClasses;
    private LinkedHashMap<Class<? extends Filter>,WebFilter> filterClasses;
    private LinkedHashMap<Filter,WebFilter> filterInstances;

    private void addServlet(final Class<? extends HttpServlet> servletClass, final HttpServlet servletInstance, WebServlet webServlet) {
      if (webServlet == null)
        webServlet = servletClass.getAnnotation(WebServlet.class);

      if (webServlet == null) {
        if (logger.isWarnEnabled()) { logger.warn("@WebServlet annotation is not provided with HttpServlet class " + servletClass.getName()); }
        return;
      }

      final String[] urlPatterns = webServlet.urlPatterns();
      if (urlPatterns == null || urlPatterns.length == 0) {
        if (logger.isWarnEnabled()) { logger.warn("URL pattern(s) are not specified on the @WebServlet annotation of the HttpServlet class " + servletClass.getName() + ". Skipping class."); }
        return;
      }

      if (servletInstance != null)
        servletInstances.put(servletInstance, webServlet);
      else
        servletClasses.put(servletClass, webServlet);
    }

    private void addFilter(final Class<? extends Filter> filterClass, final Filter filterInstance, WebFilter webFilter) {
      if (webFilter == null)
        webFilter = filterClass.getAnnotation(WebFilter.class);

      if (webFilter == null) {
        if (logger.isWarnEnabled()) { logger.warn("@WebFilter annotation is not provided with Filter class " + filterClass.getName()); }
        return;
      }

      final String[] urlPatterns = webFilter.urlPatterns();
      if (urlPatterns == null || urlPatterns.length == 0) {
        if (logger.isWarnEnabled()) { logger.warn("urlPatterns argument is null, and URL pattern(s) are not specifies on the @WebFilter annotation of the Filter class " + filterClass.getName()); }
        return;
      }

      if (filterInstance != null)
        filterInstances.put(filterInstance, webFilter);
      else
        filterClasses.put(filterClass, webFilter);
    }

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

    private boolean gzipHandler = DEFAULT_GZIP_HANDLER;

    /**
     * Returns the builder instance.
     *
     * @param gzipHandler Whether the container should have a {@link GzipHandler} automatically inflate compressed requests. Default:
     *          false.
     * @return The builder instance.
     */
    public Builder withGZipHandler(final boolean gzipHandler) {
      this.gzipHandler = gzipHandler;
      return this;
    }

    private boolean stopAtShutdown = DEFAULT_STOP_AT_SHUTDOWN;

    /**
     * Returns the builder instance.
     *
     * @param stopAtShutdown Whether the container should be explicitly stopped (and thus fulfill its graceful shutdown) when the JVM is
     *          shutdown. Default: false.
     * @return The builder instance.
     */
    public Builder withStopAtShutdown(final boolean stopAtShutdown) {
      this.stopAtShutdown = stopAtShutdown;
      return this;
    }

    private long shutdownTimeout = DEFAULT_SHUTDOWN_TIMEOUT_MS;

    /**
     * Returns the builder instance.
     *
     * @param shutdownTimeoutMs The timeout (in milliseconds) for the server to gracefully stop before exiting.
     * @return The builder instance.
     * @throws IllegalArgumentException If {@code shutdownTimeout} is negative.
     */
    public Builder withShutdownTimeout(final long shutdownTimeoutMs) {
      this.shutdownTimeout = assertNotNegative(shutdownTimeoutMs);
      return this;
    }

    private long idleTimeoutMs = DEFAULT_IDLE_TIMEOUT_MS;

    /**
     * Returns the builder instance.
     *
     * @param idleTimeoutMs The maximum idle time for a connection.
     * @return The builder instance.
     * @throws IllegalArgumentException If {@code idleTimeout} is negative.
     * @see ServerConnector#setIdleTimeout(long)
     */
    public Builder withIdleTimeout(final long idleTimeoutMs) {
      this.idleTimeoutMs = assertNotNegative(idleTimeoutMs);
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

    /**
     * Returns the builder instance.
     *
     * @param servletClasses Set of servlet classes to be registered with Jetty's web context. Calling this method with {@code null}
     *          will set the {@link #servletClasses} set to null. Calling this method multiple times with non-null values will add to
     *          (instead of replace) the {@link #servletClasses} set with the provided servlet classes.
     * @return The builder instance.
     * @implNote If the specified set is null, and the {@link #servletClasses} set is null, the {@link EmbeddedJetty9} will scan
     *           candidate packages for {@link HttpServlet} classes to load automatically.
     */
    public Builder withServletClasses(final Set<Class<? extends HttpServlet>> servletClasses) {
      if (servletClasses != null) {
        if (this.servletClasses == null)
          this.servletClasses = new LinkedHashMap<>(servletClasses.size() * 2);

        if (servletClasses.size() > 0)
          for (final Class<? extends HttpServlet> servletClass : servletClasses) // [S]
            addServlet(servletClass, null, null);
      }
      else {
        this.servletClasses = null;
      }

      return this;
    }

    /**
     * Returns the builder instance.
     *
     * @param servletClasses Array of servlet classes to be registered with Jetty's web context. Calling this method with {@code null}
     *          will set the {@link #servletClasses} set to null. Calling this method multiple times with non-null values will add to
     *          (instead of replace) the {@link #servletClasses} set with the provided servlet classes.
     * @return The builder instance.
     * @implNote If the specified set is null, and the {@link #servletClasses} array is null, the {@link EmbeddedJetty9} will scan
     *           candidate packages for {@link HttpServlet} classes to load automatically.
     */
    @SafeVarargs
    public final Builder withServletClasses(final Class<? extends HttpServlet> ... servletClasses) {
      if (servletClasses != null) {
        if (this.servletClasses == null)
          this.servletClasses = new LinkedHashMap<>(servletClasses.length * 2);

        for (final Class<? extends HttpServlet> servletClass : servletClasses) // [A]
          addServlet(servletClass, null, null);
      }
      else {
        this.servletClasses = null;
      }

      return this;
    }

    /**
     * Returns the builder instance.
     *
     * @param servletClass Servlet class to be registered with Jetty's web context. Calling this method multiple times will add to
     *          (instead of replace) the {@link #servletClasses} set with the provided servlet class.
     * @param webServlet The {@link WebServlet} annotation instance specifying the provided servlet class's configuration. If
     *          {@code null}, {@link EmbeddedJetty9} will dereference the the {@link WebServlet} annotation present on the specified
     *          servlet class.
     * @return The builder instance.
     * @throws NullPointerException If {@code servletClass} is null.
     * @throws IllegalArgumentException If {@code urlPatterns} is an empty array.
     */
    public final Builder withServletClass(final Class<? extends HttpServlet> servletClass, final WebServlet webServlet) {
      if (this.servletClasses == null)
        this.servletClasses = new LinkedHashMap<>();

      addServlet(servletClass, null, webServlet);
      return this;
    }

    /**
     * Returns the builder instance.
     *
     * @param servletInstances Set of servlet instances to be registered with Jetty's web context. Calling this method with {@code null}
     *          will set the {@link #servletInstances} set to null. Calling this method multiple times with non-null values will add to
     *          (instead of replace) the {@link #servletInstances} set with the provided servlet instances.
     * @return The builder instance.
     * @implNote If the specified set is null, and the {@link #servletInstances} set is null, the {@link EmbeddedJetty9} will scan
     *           candidate packages for {@link HttpServlet} classes to load automatically.
     */
    public Builder withServletInstances(final Set<HttpServlet> servletInstances) {
      if (servletInstances != null) {
        if (this.servletInstances == null)
          this.servletInstances = new LinkedHashMap<>(servletInstances.size() * 2);

        if (servletInstances.size() > 0)
          for (final HttpServlet servletInstance : servletInstances) // [S]
            addServlet(servletInstance.getClass(), servletInstance, null);
      }
      else {
        this.servletInstances = null;
      }

      return this;
    }

    /**
     * Returns the builder instance.
     *
     * @param servletInstances Array of servlet instances to be registered with Jetty's web context. Calling this method multiple times
     *          will add to (instead of replace) the {@link #servletInstances} set with the provided servlet instances.
     * @return The builder instance.
     * @implNote If the specified array is null, and the {@link #servletInstances} set is null, the {@link EmbeddedJetty9} will scan
     *           candidate packages for {@link HttpServlet} classes to load automatically.
     */
    public Builder withServletInstances(final HttpServlet ... servletInstances) {
      if (servletInstances != null) {
        if (this.servletInstances == null)
          this.servletInstances = new LinkedHashMap<>(servletInstances.length * 2);

        for (final HttpServlet servletInstance : servletInstances) // [A]
          addServlet(servletInstance.getClass(), servletInstance, null);
      }
      else {
        this.servletInstances = null;
      }

      return this;
    }

    /**
     * Returns the builder instance.
     *
     * @param servletInstance Servlet instance to be registered with Jetty's web context. Calling this method multiple times will add to
     *          (instead of replace) the {@link #servletInstances} set with the provided servlet instance.
     * @param webServlet The {@link WebServlet} annotation instance specifying the provided servlet instance's configuration. If
     *          {@code null}, {@link EmbeddedJetty9} will dereference the the {@link WebServlet} annotation present on the class of the
     *          specified servlet instance.
     * @return The builder instance.
     * @throws NullPointerException If {@code servletInstance} is null.
     * @throws IllegalArgumentException If {@code urlPatterns} is an empty array.
     */
    public Builder withServletInstance(final HttpServlet servletInstance, final WebServlet webServlet) {
      if (this.servletInstances == null)
        this.servletInstances = new LinkedHashMap<>();

      this.servletInstances.put(servletInstance, webServlet);
      return this;
    }

    /**
     * Returns the builder instance.
     *
     * @param filterClasses Set of filter classes to be registered with Jetty's web context. Calling this method with {@code null} will
     *          set the {@link #filterClasses} set to null. Calling this method multiple times with non-null values will add to (instead
     *          of replace) the {@link #filterClasses} set with the provided filter classes.
     * @return The builder instance.
     * @implNote If the specified set is null, and the {@link #filterClasses} set is null, the {@link EmbeddedJetty9} will scan
     *           candidate packages for {@link Filter} classes to load automatically.
     */
    public Builder withFilterClasses(final Set<Class<? extends Filter>> filterClasses) {
      if (servletClasses != null) {
        if (this.servletClasses == null)
          this.servletClasses = new LinkedHashMap<>(filterClasses.size() * 2);

        if (servletClasses.size() > 0)
          for (final Class<? extends Filter> filterClass : filterClasses) // [S]
            addFilter(filterClass, null, null);
      }
      else {
        this.servletClasses = null;
      }

      return this;
    }

    /**
     * Returns the builder instance.
     *
     * @param filterClasses Array of filter classes to be registered with Jetty's web context. Calling this method with {@code null}
     *          will set the {@link #filterClasses} set to null. Calling this method multiple times with non-null values will add to
     *          (instead of replace) the {@link #filterClasses} set with the provided filter classes.
     * @return The builder instance.
     * @implNote If the specified set is null, and the {@link #filterClasses} array is null, the {@link EmbeddedJetty9} will scan
     *           candidate packages for {@link Filter} classes to load automatically.
     */
    @SafeVarargs
    public final Builder withFilterClasses(final Class<? extends Filter> ... filterClasses) {
      if (filterClasses != null) {
        if (this.filterClasses == null)
          this.filterClasses = new LinkedHashMap<>(filterClasses.length * 2);

        for (final Class<? extends Filter> filterClass : filterClasses) // [A]
          addFilter(filterClass, null, null);
      }
      else {
        this.filterClasses = null;
      }

      return this;
    }

    /**
     * Returns the builder instance.
     *
     * @param filterClass Filter class to be registered with Jetty's web context. Calling this method multiple times will add to
     *          (instead of replace) the {@link #filterClasses} set with the provided filter class.
     * @param webFilter The {@link WebFilter} annotation instance specifying the provided filter class's configuration. If {@code null},
     *          {@link EmbeddedJetty9} will dereference the the {@link WebFilter} annotation present on the specified filter class.
     * @return The builder instance.
     * @throws NullPointerException If {@code filterClass} is null.
     * @throws IllegalArgumentException If {@code urlPatterns} is an empty array.
     */
    public final Builder withFilterClass(final Class<? extends Filter> filterClass, final WebFilter webFilter) {
      if (this.filterClasses == null)
        this.filterClasses = new LinkedHashMap<>();

      addFilter(filterClass, null, webFilter);
      return this;
    }

    /**
     * Returns the builder instance.
     *
     * @param filterInstances Set of filter instances to be registered with Jetty's web context. Calling this method with {@code null}
     *          will set the {@link #filterInstances} set to null. Calling this method multiple times with non-null values will add to
     *          (instead of replace) the {@link #filterInstances} set with the provided filter instances.
     * @return The builder instance.
     * @implNote If the specified set is null, and the {@link #filterInstances} set is null, the {@link EmbeddedJetty9} will scan
     *           candidate packages for {@link Filter} classes to load automatically.
     */
    public Builder withFilterInstances(final Set<Filter> filterInstances) {
      if (filterInstances != null) {
        if (this.filterInstances == null)
          this.filterInstances = new LinkedHashMap<>(filterInstances.size() * 2);

        if (filterInstances.size() > 0)
          for (final Filter filterInstance : filterInstances) // [S]
            addFilter(filterInstance.getClass(), filterInstance, null);
      }
      else {
        this.filterInstances = null;
      }

      return this;
    }

    /**
     * Returns the builder instance.
     *
     * @param filterInstances Array of filter instances to be registered with Jetty's web context. Calling this method multiple times
     *          will add to (instead of replace) the {@link #filterInstances} set with the provided filter instances.
     * @return The builder instance.
     * @implNote If the specified array is null, and the {@link #filterInstances} set is null, the {@link EmbeddedJetty9} will scan
     *           candidate packages for {@link Filter} classes to load automatically.
     */
    public Builder withFilterInstances(final Filter ... filterInstances) {
      if (filterInstances != null) {
        if (this.filterInstances == null)
          this.filterInstances = new LinkedHashMap<>(filterInstances.length * 2);

        for (final Filter filterInstance : filterInstances) // [A]
          addFilter(filterInstance.getClass(), filterInstance, null);
      }
      else {
        this.filterInstances = null;
      }

      return this;
    }

    /**
     * Returns the builder instance.
     *
     * @param filterInstance Filter instance to be registered with Jetty's web context. Calling this method multiple times will add to
     *          (instead of replace) the {@link #filterInstances} set with the provided filter instance.
     * @param webFilter The {@link WebFilter} annotation instance specifying the provided filter instance's configuration. If
     *          {@code null}, {@link EmbeddedJetty9} will dereference the the {@link WebFilter} annotation present on the class of the
     *          specified filter instance.
     * @return The builder instance.
     * @throws NullPointerException If {@code servletInstance} is null.
     * @throws IllegalArgumentException If {@code urlPatterns} is an empty array.
     */
    public Builder withFilterInstance(final Filter filterInstance, final WebFilter webFilter) {
      if (this.filterInstances == null)
        this.filterInstances = new LinkedHashMap<>();

      this.filterInstances.put(filterInstance, webFilter);
      return this;
    }

    /**
     * Returns a new {@link EmbeddedJetty9} with the configuration in this builder instance.
     *
     * @return A new {@link EmbeddedJetty9} with the configuration in this builder instance.
     */
    public EmbeddedJetty9 build() {
      return new EmbeddedJetty9(port, contextPath, keyStorePath, keyStorePassword, externalResourcesAccess, http2, gzipHandler, stopAtShutdown, shutdownTimeout, idleTimeoutMs, realm, uncaughtServletExceptionHandler, servletClasses, servletInstances, filterClasses, filterInstances);
    }
  }

  private final Server server;

  /**
   * Creates a new {@link EmbeddedJetty9} with the specified port. The {@link EmbeddedJetty9} will scan all classes of the context
   * class loader to automatically locate servlet and filter classes.
   *
   * @param port The listen port, which must be between 0 and 65535. A value of 0 advises Jetty to set a random port that is
   *          available. The port can thereafter be determined with {@link #getPort()}.
   * @param uncaughtServletExceptionHandler Handler to be used for uncaught servlet exceptions.
   * @throws IllegalArgumentException If port is not between 0 and 65535.
   */
  public EmbeddedJetty9(final int port, final UncaughtServletExceptionHandler uncaughtServletExceptionHandler) {
    this(port, DEFAULT_CONTEXT_PATH, null, null, DEFAULT_EXTERNAL_RESOURCE_ACCESS, DEFAULT_HTTP2, DEFAULT_GZIP_HANDLER, DEFAULT_STOP_AT_SHUTDOWN, DEFAULT_SHUTDOWN_TIMEOUT_MS, DEFAULT_IDLE_TIMEOUT_MS, null, uncaughtServletExceptionHandler, null, null, null, null);
  }

  /**
   * Creates a new {@link EmbeddedJetty9} with the specified port, and servlet and filter classes to be registered with Jetty's web
   * context.
   *
   * @param port The listen port, which must be between 0 and 65535. A value of 0 advises Jetty to set a random port that is
   *          available. The port can thereafter be determined with {@link #getPort()}.
   * @param uncaughtServletExceptionHandler Handler to be used for uncaught servlet exceptions.
   * @param servletClasses Set of servlet classes to be registered with Jetty's web context. If the specified set is null, and the
   *          {@code servletInstances} set is null, the {@link EmbeddedJetty9} will scan candidate packages for {@link HttpServlet}
   *          classes to load automatically.
   * @param servletInstances Set of servlet instances to be registered with Jetty's web context. If the specified set is null, and the
   *          {@code servletInstances} set is null, the {@link EmbeddedJetty9} will scan candidate packages for {@link HttpServlet}
   *          classes to load automatically.
   * @param filterClasses Set of filter classes to be registered with Jetty's web context. If the specified set is null, and the
   *          {@code filterInstances} set is null, the {@link EmbeddedJetty9} will scan candidate packages for {@link Filter} classes
   *          to load automatically.
   * @param filterInstances Set of filter instances to be registered with Jetty's web context. If the specified set is null, and the
   *          {@code filterInstances} set is null, the {@link EmbeddedJetty9} will scan candidate packages for {@link Filter} classes
   *          to load automatically.
   * @throws IllegalArgumentException If port is not between 0 and 65535.
   */
  public EmbeddedJetty9(
    final int port,
    final UncaughtServletExceptionHandler uncaughtServletExceptionHandler,
    final LinkedHashMap<Class<? extends HttpServlet>,WebServlet> servletClasses,
    final LinkedHashMap<HttpServlet,WebServlet> servletInstances,
    final LinkedHashMap<Class<? extends Filter>,WebFilter> filterClasses,
    final LinkedHashMap<Filter,WebFilter> filterInstances
  ) {
    this(port, DEFAULT_CONTEXT_PATH, null, null, DEFAULT_EXTERNAL_RESOURCE_ACCESS, DEFAULT_HTTP2, DEFAULT_GZIP_HANDLER, DEFAULT_STOP_AT_SHUTDOWN, DEFAULT_SHUTDOWN_TIMEOUT_MS, DEFAULT_IDLE_TIMEOUT_MS, null, uncaughtServletExceptionHandler, servletClasses, servletInstances, filterClasses, filterInstances);
  }

  /**
   * Creates a new {@link EmbeddedJetty9} with the specified port, and servlet and filter classes to be registered with Jetty's web
   * context.
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
   * @param withGzipHandler Whether the container should have a {@link GzipHandler} automatically inflate compressed requests.
   * @param stopAtShutdown Whether the container should be explicitly stopped (and thus fulfill its graceful shutdown) when the JVM is
   *          shutdown.
   * @param shutdownTimeoutMs The timeout (in milliseconds) for the server to gracefully stop before exiting.
   * @param idleTimeoutMs The maximum idle time for a connection. See {@link ServerConnector#setIdleTimeout(long)}.
   * @param realm The realm of roles and credentials.
   * @param uncaughtServletExceptionHandler Handler to be used for uncaught servlet exceptions.
   * @param servletClassToUrlPatterns Set of servlet classes to be registered with Jetty's web context. If the specified set is null,
   *          and the {@code servletInstances} set is null, the {@link EmbeddedJetty9} will scan candidate packages for
   *          {@link HttpServlet} classes to load automatically.
   * @param servletInstanceToUrlPatterns Set of servlet instances to be registered with Jetty's web context. If the specified set is
   *          null, and the {@code servletInstances} set is null, the {@link EmbeddedJetty9} will scan candidate packages for
   *          {@link HttpServlet} classes to load automatically.
   * @param filterClassToUrlPatterns Set of filter classes to be registered with Jetty's web context. If the specified set is null,
   *          and the {@code filterInstances} set is null, the {@link EmbeddedJetty9} will scan candidate packages for {@link Filter}
   *          classes to load automatically.
   * @param filterInstanceToUrlPatterns Set of filter instances to be registered with Jetty's web context. If the specified set is
   *          null, and the {@code filterInstances} set is null, the {@link EmbeddedJetty9} will scan candidate packages for
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
    final boolean withGzipHandler,
    final boolean stopAtShutdown,
    final long shutdownTimeoutMs,
    final long idleTimeoutMs,
    final Realm realm,
    final UncaughtServletExceptionHandler uncaughtServletExceptionHandler,
    final Map<Class<? extends HttpServlet>,WebServlet> servletClassToUrlPatterns,
    final Map<HttpServlet,WebServlet> servletInstanceToUrlPatterns,
    final Map<Class<? extends Filter>,WebFilter> filterClassToUrlPatterns,
    final Map<Filter,WebFilter> filterInstanceToUrlPatterns
  ) {
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
    if (withGzipHandler) {
      final GzipHandler gzipHandler = new GzipHandler();
      gzipHandler.setInflateBufferSize(1024);
      contextHandler.setGzipHandler(gzipHandler);
    }

    contextHandler.setContextPath(contextPath);
    addAllServlets(contextHandler, uncaughtServletExceptionHandler, servletClassToUrlPatterns, servletInstanceToUrlPatterns, filterClassToUrlPatterns, filterInstanceToUrlPatterns);
    addConnectors(server, port, http2, idleTimeoutMs, keyStorePath, keyStorePassword);
    handlers.addHandler(contextHandler);

    server.setHandler(handlers);

    server.setStopTimeout(shutdownTimeoutMs);
    if (stopAtShutdown) {
      server.setStopAtShutdown(true);

      final StatisticsHandler statisticsHandler = new StatisticsHandler();
      statisticsHandler.setHandler(server.getHandler());
      server.setHandler(statisticsHandler);
    }

    // Look at the javadoc for CustomRequestLog. There is no special case handling of "proxiedForAddress",
    // which relies on ForwardRequestCustomizer. For Log Latency, see "%D" formatting option.
    // final CustomRequestLog requestLog = new CustomRequestLog(new Slf4jRequestLogWriter(), CustomRequestLog.EXTENDED_NCSA_FORMAT);

    final Slf4jRequestLog requestLog = new Slf4jRequestLog();
    requestLog.setPreferProxiedForAddress(true);
    server.setRequestLog(requestLog);
  }

  /**
   * Creates a new {@link EmbeddedJetty9} from the specified {@link Builder}.
   *
   * @param builder The {@link Builder}.
   */
  public EmbeddedJetty9(final EmbeddedJetty9.Builder builder) {
    this(builder.port, builder.contextPath, builder.keyStorePath, builder.keyStorePassword, builder.externalResourcesAccess, builder.http2, builder.gzipHandler, builder.stopAtShutdown, builder.shutdownTimeout, builder.idleTimeoutMs, builder.realm, builder.uncaughtServletExceptionHandler, builder.servletClasses, builder.servletInstances, builder.filterClasses, builder.filterInstances);
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