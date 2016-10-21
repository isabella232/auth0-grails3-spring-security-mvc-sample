package com.auth0.example

import org.springframework.boot.autoconfigure.security.SecurityProperties
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity

@Configuration
@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
class AppConfig extends com.auth0.spring.security.mvc.Auth0Config {

    @Override
    protected void authorizeRequests(final HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/", "/css/**", "/fonts/**", "/assets/**", "/login").permitAll()
                .antMatchers("/portal/**").hasAnyAuthority("ROLE_USER", "ROLE_ADMIN")
                .antMatchers(securedRoute).authenticated()
    }
}
