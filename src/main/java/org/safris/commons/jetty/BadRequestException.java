package org.safris.commons.jetty;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;

public class BadRequestException extends WebApplicationException {
  private static final long serialVersionUID = -2151324269770192251L;

  public BadRequestException(final Throwable cause) {
    super(cause, Response.Status.BAD_REQUEST);
  }
}