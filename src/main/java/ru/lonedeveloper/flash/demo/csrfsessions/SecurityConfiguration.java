package ru.lonedeveloper.flash.demo.csrfsessions;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfTokenRepository;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    public static final String USER = "user";
    public static final String PASSWORD = "password";

    @Override
    public void configure(final WebSecurity web) throws Exception {
        web.debug(true);
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        super.configure(http);

        final CsrfTokenRepository csrfTokenRepository = new CookieCsrfTokenRepository();

        http.csrf().csrfTokenRepository(csrfTokenRepository);
        http.sessionManagement().disable();
        /*
         * Add CsrfAuthenticationStrategy to plug into AbstractAuthenticationProcessingFilter which is not done by
         * CsrfConfigurer when session management is disabled. See
         * https://docs.spring.io/spring-security/site/docs/current/reference/html/session-mgmt.html#
         * sessionauthenticationstrategy
         */
        http.setSharedObject(SessionAuthenticationStrategy.class, new CsrfAuthenticationStrategy(csrfTokenRepository));
    }

    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser(USER).password(PASSWORD).roles("USER", "ACTUATOR");
    }

}
