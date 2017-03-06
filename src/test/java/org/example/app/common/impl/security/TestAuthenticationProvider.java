package org.example.app.common.impl.security;

import java.util.Arrays;

import javax.inject.Named;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@Named
public class TestAuthenticationProvider implements AuthenticationProvider {

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {

    String login = authentication.getPrincipal().toString();
    final String password = login;
    if (!password.equals(authentication.getCredentials())) {
      throw new BadCredentialsException("Wrong password!");
    }
    return new UsernamePasswordAuthenticationToken(login, "pwd", Arrays.asList(new SimpleGrantedAuthority("test")));
  }

  @Override
  public boolean supports(Class<?> authentication) {

    return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
  }

}
