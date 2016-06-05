package org.safris.commons.jetty;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;

public class UnauthorizedException extends WebApplicationException {
  private static final long serialVersionUID = -2151324269770192251L;

  public UnauthorizedException() {
    this("Please authenticate.", "VNUE");
  }

  public UnauthorizedException(final String message, final String realm) {
    super(Response.status(Response.Status.UNAUTHORIZED).header(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"" + realm + "\"").entity(message).build());
  }
}