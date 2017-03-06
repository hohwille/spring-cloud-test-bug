package org.example.app.common.impl.web;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.inject.Named;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;

@Named
public class ZuulAuthorizationFilter extends ZuulFilter {

  private static final Pattern PATTERN_PUBLIC = Pattern.compile("/[a-z][a-z0-9]*/public/.*");

  @Override
  public String filterType() {

    return "route";
  }

  @Override
  public int filterOrder() {

    return 1;
  }

  @Override
  public boolean shouldFilter() {

    RequestContext ctx = RequestContext.getCurrentContext();
    HttpServletRequest request = ctx.getRequest();
    String contextPath = request.getServletPath();
    Matcher matcher = PATTERN_PUBLIC.matcher(contextPath);
    if (matcher.matches()) {
      return false;
    }
    String app = getFirstSegment(contextPath);
    if (app == null) {
      return false;
    }
    boolean authorized = isAuthorized(contextPath, app);
    return !authorized;
  }

  private boolean isAuthorized(String contextPath, String app) {

    if (app != null) {
      Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
      if (authentication == null) {
        return false;
      }
      if (!isAuthorized(authentication, app)) {
        return false;
      }
    }
    return true;
  }

  @Override
  public Object run() {

    RequestContext ctx = RequestContext.getCurrentContext();
    HttpServletResponse response = ctx.getResponse();
    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
    ctx.setSendZuulResponse(false);
    return null;
  }

  private String getFirstSegment(String contextPath) {

    if (contextPath.startsWith("/")) {
      int indexOfSecondSlash = contextPath.indexOf('/', 1);
      if (indexOfSecondSlash > 0) {
        String app = contextPath.substring(1, indexOfSecondSlash);
        return app;
      } else {
        return contextPath.substring(1);
      }
    }
    return null;
  }

  private boolean isAuthorized(Authentication authentication, String app) {

    for (GrantedAuthority authority : authentication.getAuthorities()) {
      if (authority.toString().equals(app)) {
        return true;
      }
    }
    return false;
  }
}
