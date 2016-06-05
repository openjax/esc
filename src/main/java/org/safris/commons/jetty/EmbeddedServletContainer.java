/* Copyright (c) 2016 Seva Safris
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

package org.safris.commons.jetty;

import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Set;
import java.util.logging.Logger;

import javax.servlet.DispatcherType;
import javax.servlet.Filter;
import javax.servlet.annotation.HttpConstraint;
import javax.servlet.annotation.ServletSecurity;
import javax.servlet.annotation.WebFilter;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;

import org.eclipse.jetty.security.ConstraintMapping;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.security.SecurityHandler;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.security.Constraint;
import org.safris.commons.lang.PackageLoader;
import org.safris.commons.servlet.xe.$se_realm;

public class EmbeddedServletContainer extends EmbeddedServletContext {
  private static final Logger logger = Logger.getLogger(EmbeddedServletContainer.class.getName());
  private static UncaughtServletExceptionHandler uncaughtServletExceptionHandler;

  @SuppressWarnings("unchecked")
  private static ServletContextHandler addAllServlets(final Package[] packages, final $se_realm realm) {
    final ServletContextHandler context = createServletContextHandler(realm);
    try {
      for (final Package pkg : packages) {
        Set<Class<?>> classes;
        try {
          classes = PackageLoader.getSystemPackageLoader().loadPackage(pkg, false);
        }
        catch (final SecurityException e) {
          continue;
        }
        WebServlet webServlet;
        WebFilter webFilter;
        for (final Class<?> cls : classes) {
          if (Modifier.isAbstract(cls.getModifiers()))
            continue;

          // Add a HttpServlet with a @WebServlet annotation
          if (HttpServlet.class.isAssignableFrom(cls) && (webServlet = cls.getAnnotation(WebServlet.class)) != null && webServlet.urlPatterns() != null && webServlet.urlPatterns().length > 0) {
            final HttpServlet servlet = (HttpServlet)cls.newInstance();
            final ServletSecurity servletSecurity = cls.getAnnotation(ServletSecurity.class);
            HttpConstraint httpConstraint;
            if (servletSecurity != null && (httpConstraint = servletSecurity.value()) != null && httpConstraint.rolesAllowed().length > 0) {
              for (final String urlPattern : webServlet.urlPatterns()) {
                for (final String role : httpConstraint.rolesAllowed()) {
                  final ConstraintMapping constraintMapping = new ConstraintMapping();
                  constraintMapping.setConstraint(getBasicAuthConstraint(Constraint.__BASIC_AUTH, role));
                  constraintMapping.setPathSpec(urlPattern);
                  final SecurityHandler securityHandler = context.getSecurityHandler();
                  if (!(securityHandler instanceof ConstraintSecurityHandler))
                    throw new Error("SecurityHandler of ServletContextHandler must be a ConstraintSecurityHandler, did you call setConstraintSecurityHandler()?");

                  ((ConstraintSecurityHandler)securityHandler).addConstraintMapping(constraintMapping);
                }
              }

              logger.info(servlet.getClass().getSimpleName() + " [" + context.getSecurityHandler().getLoginService().getName() + "]: " + Arrays.toString(webServlet.urlPatterns()));
            }

            logger.info(cls.getName() + " " + Arrays.toString(webServlet.urlPatterns()));
            for (final String urlPattern : webServlet.urlPatterns())
              context.addServlet(new ServletHolder(servlet), urlPattern);
          }
          // Add a Filter with a @WebFilter annotation
          else if (Filter.class.isAssignableFrom(cls) && (webFilter = cls.getAnnotation(WebFilter.class)) != null && webFilter.urlPatterns() != null && webFilter.urlPatterns().length > 0) {
            logger.info(cls.getName() + " " + Arrays.toString(webFilter.urlPatterns()));
            for (final String urlPattern : webFilter.urlPatterns()) {
              context.addFilter((Class<? extends Filter>)cls, urlPattern, webFilter.dispatcherTypes().length > 0 ? EnumSet.of(webFilter.dispatcherTypes()[0], webFilter.dispatcherTypes()) : EnumSet.noneOf(DispatcherType.class));
            }
          }
        }
      }

      return context;
    }
    catch (final Exception e) {
      throw new Error(e);
    }
  }

  public static void setUncaughtServletExceptionHandler(final UncaughtServletExceptionHandler uncaughtServletExceptionHandler) {
    EmbeddedServletContainer.uncaughtServletExceptionHandler = uncaughtServletExceptionHandler;
  }

  protected static UncaughtServletExceptionHandler getUncaughtServletExceptionHandler() {
    return EmbeddedServletContainer.uncaughtServletExceptionHandler;
  }

  public EmbeddedServletContainer(final int port, final String keyStorePath, final String keyStorePassword, final boolean externalResourcesAccess, final $se_realm realm) {
    super(port, keyStorePath, keyStorePassword, externalResourcesAccess, addAllServlets(Package.getPackages(), realm));
  }
}