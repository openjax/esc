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

import java.io.IOException;

import javax.servlet.DispatcherType;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;

@WebFilter(filterName = "UncaughtServletExceptionFilter", urlPatterns = {"/*"}, dispatcherTypes = {DispatcherType.REQUEST})
public class UncaughtServletExceptionFilter implements Filter {
  @Override
  public void init(final FilterConfig filterConfig) throws ServletException {
  }

  @Override
  public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain) throws IOException, ServletException {
    final UncaughtServletExceptionHandler uncaughtExceptionHandler = EmbeddedServletContainer.getUncaughtServletExceptionHandler();
    try {
      chain.doFilter(request, response);
    }
    catch (final Exception e1) {
      if (uncaughtExceptionHandler != null) {
        try {
          uncaughtExceptionHandler.uncaughtServletException(request, response, e1);
        }
        catch (final Throwable e2) {
          if (e2 instanceof IOException)
            throw (IOException)e2;

          if (e2 instanceof ServletException)
            throw (ServletException)e2;

          if (e2 instanceof RuntimeException)
            throw (RuntimeException)e2;
        }
      }
      else {
        throw e1;
      }
    }
  }

  @Override
  public void destroy() {
  }
}