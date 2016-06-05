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
import java.util.Set;
import java.util.logging.Logger;

import javax.ws.rs.Path;
import javax.ws.rs.container.ContainerRequestFilter;

import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.safris.commons.lang.PackageLoader;
import org.safris.commons.servlet.xe.$se_realm;

public class EmbeddedRESTServer extends EmbeddedServletContext {
  private static final Logger logger = Logger.getLogger(EmbeddedRESTServer.class.getName());

  public EmbeddedRESTServer(final int port, final String keyStorePath, final String keyStorePassword, final boolean externalResourcesAccess, final $se_realm realm) {
    super(port, keyStorePath, keyStorePassword, externalResourcesAccess, addAllServlets(Package.getPackages(), realm));
  }

  private static ServletContextHandler addAllServlets(final Package[] packages, final $se_realm realm) {
    final ResourceConfig resourceConfig = new ResourceConfig();
    try {
      for (final Package pkg : packages) {
        Set<Class<?>> classes;
        try {
          classes = PackageLoader.getSystemPackageLoader().loadPackage(pkg, false);
        }
        catch (final SecurityException e) {
          continue;
        }
        Path path;
        for (final Class<?> cls : classes) {
          if (Modifier.isAbstract(cls.getModifiers()))
            continue;

          // Add a HttpServlet with a @WebServlet annotation
          if ((path = cls.getAnnotation(Path.class)) != null) {
            resourceConfig.register(cls);
            logger.info(cls.getName() + " " + path.value());
          }
          // Add a Filter with a @WebFilter annotation
          else if (ContainerRequestFilter.class.isAssignableFrom(cls)) {
            logger.info(cls.getName());
            resourceConfig.register(cls);
          }
        }
      }

      final ServletHolder holder = new ServletHolder(new ServletContainer(resourceConfig));
//      holder.setInitParameter("com.sun.jersey.config.property.resourceConfigClass", "com.sun.jersey.api.core.PackagesResourceConfig");
//
//      holder.setInitParameter("com.sun.jersey.config.property.packages", "package.where.your.service.classes.are");

      // un-comment these to enable tracing of requests and responses

//      holder.setInitParameter("com.sun.jersey.config.feature.Debug", "true");
//      holder.setInitParameter("com.sun.jersey.config.feature.Trace", "true");
//
//      holder.setInitParameter("com.sun.jersey.spi.container.ContainerRequestFilters", "com.sun.jersey.api.container.filter.LoggingFilter");
//      holder.setInitParameter("com.sun.jersey.spi.container.ContainerResponseFilters", "com.sun.jersey.api.container.filter.LoggingFilter");

      ServletContextHandler context = new ServletContextHandler(ServletContextHandler.NO_SESSIONS);
      context.setContextPath("/");
      context.addServlet(holder, "/*");
      return context;
    }
    catch (final Exception e) {
      throw new Error(e);
    }
  }
}