package org.example.app.common.impl.security;

import java.util.LinkedHashMap;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

public abstract class AbstractWebSecurityConfig extends WebSecurityConfigurerAdapter {

  @Override
  protected abstract void configure(AuthenticationManagerBuilder auth) throws Exception;

  @Override
  public void configure(HttpSecurity http) throws Exception {

    HttpSecurity security = http;
    security = configureAuthorizeRequests(security);
    security = configureCsrf(security);
    security = configureLogin(security);
    security = configureAuthenticationExceptions(security);
    security = configureLogout(security);
    security = configureHeaders(security);
  }

  protected HttpSecurity configureAuthorizeRequests(HttpSecurity http) throws Exception {

    return configureAuthorizeRequests(http.authorizeRequests()).and();
  }

  protected ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry configureAuthorizeRequests(
      ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry authorizeRequests) {

    return authorizeRequests.antMatchers("/public").permitAll().anyRequest().authenticated() //
        .antMatchers("/").permitAll().anyRequest().authenticated();
  }

  protected HttpSecurity configureCsrf(HttpSecurity http) throws Exception {

    return http; // .csrf().requireCsrfProtectionMatcher(csrfProtectionMatcher()).and();
  }

  protected HttpSecurity configureLogin(HttpSecurity http) throws Exception {

    return http.formLogin().successHandler(accessAuthenticationSuccessHandler()) //
        .failureUrl("/login?error").and();
  }

  protected HttpSecurity configureAuthenticationExceptions(HttpSecurity http) throws Exception {

    return configureAuthenticationExceptions(http.exceptionHandling()).and();
  }

  protected ExceptionHandlingConfigurer<HttpSecurity> configureAuthenticationExceptions(
      ExceptionHandlingConfigurer<HttpSecurity> exceptionHandling) throws Exception {

    return exceptionHandling.authenticationEntryPoint(accessAuthenticationEntryPoint());
  }

  protected HttpSecurity configureLogout(HttpSecurity security) throws Exception {

    return configureLogout(security.logout()).and();
  }

  protected LogoutConfigurer<HttpSecurity> configureLogout(LogoutConfigurer<HttpSecurity> logout) throws Exception {

    return logout; // .logoutSuccessHandler(new LogoutSuccessHandlerReturningOkHttpStatusCode());
  }

  protected HttpSecurity configureHeaders(HttpSecurity security) throws Exception {

    return security.headers().frameOptions().disable().and().headers().cacheControl().disable().and();
  }

  protected AuthenticationSuccessHandler accessAuthenticationSuccessHandler() {

    SimpleUrlAuthenticationSuccessHandler authenticationSuccessHandler = new SimpleUrlAuthenticationSuccessHandler();
    authenticationSuccessHandler.setTargetUrlParameter("targetUrl");
    return authenticationSuccessHandler;
  }

  protected AuthenticationEntryPoint accessAuthenticationEntryPoint() {

    LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPoints = new LinkedHashMap<>();
    entryPoints.put(new AntPathRequestMatcher("/**/services/**"), new Http403ForbiddenEntryPoint());

    return new DelegatingAuthenticationEntryPoint(entryPoints);
  }
}
