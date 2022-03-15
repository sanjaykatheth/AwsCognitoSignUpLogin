package com.awscognito.config;

import java.util.Arrays;
import java.util.List;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    public static final String SIGNUP_URL = "/api/signUp";
    public static final String SIGNIN_URL = "/api/login";
    public static final String verify = "/api/verify";
    public static final String forgotpassword = "/api/forgotpassword";
    public static final String confirmpassword = "/api/confirmpassword";
    public static final String redirected = "/redirected";  

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        List<String> permitAllEndpointList = Arrays.asList(SIGNUP_URL, SIGNIN_URL,verify,forgotpassword,confirmpassword,redirected);

        http.cors().and().csrf().disable()
                .authorizeRequests(expressionInterceptUrlRegistry -> expressionInterceptUrlRegistry
                        .antMatchers(permitAllEndpointList
                                .toArray(new String[permitAllEndpointList.size()]))
                        .permitAll().anyRequest().authenticated())
                .oauth2ResourceServer().jwt();
    }
}
