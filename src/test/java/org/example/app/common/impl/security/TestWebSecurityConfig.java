package org.example.app.common.impl.security;

import org.example.app.common.impl.security.AbstractDefaultWebSecurityConfig;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@Configuration
@EnableWebSecurity
public class TestWebSecurityConfig extends AbstractDefaultWebSecurityConfig {

}
