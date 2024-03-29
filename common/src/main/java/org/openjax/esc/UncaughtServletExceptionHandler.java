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

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * Handler for uncaught servlet exceptions.
 */
@FunctionalInterface
public interface UncaughtServletExceptionHandler {
  /**
   * Called by the servlet container in the event of an uncaught servlet exception.
   *
   * @param request The {@link ServletRequest} associated with the exception.
   * @param response The {@link ServletResponse} associated with the exception.
   * @param e The exception.
   */
  void uncaughtServletException(ServletRequest request, ServletResponse response, Exception e);
}