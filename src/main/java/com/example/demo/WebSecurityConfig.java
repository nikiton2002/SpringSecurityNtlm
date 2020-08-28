package com.example.demo;

import com.example.demo.web.resource.auth.NtlmAuthenticationConverter;
import com.example.demo.web.resource.auth.NtlmAuthenticationProcessingFilter;
import com.example.demo.web.resource.auth.NtlmAuthenticationProvider;
import jcifs.CIFSException;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;


@Configuration
@EnableWebSecurity
@Order(SecurityProperties.BASIC_AUTH_ORDER)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .addFilterBefore(
                        ntlmAuthenticationProcessingFilter(authenticationManagerBean()),
                        BasicAuthenticationFilter.class);
    }

    @Override
    public void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(ntlmAuthenticationProvider());
    }

    @Bean
    public NtlmAuthenticationProvider ntlmAuthenticationProvider() {
        return new NtlmAuthenticationProvider();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public NtlmAuthenticationProcessingFilter ntlmAuthenticationProcessingFilter(AuthenticationManager authenticationManager) throws CIFSException {
        NtlmAuthenticationProcessingFilter filter = new NtlmAuthenticationProcessingFilter(authenticationManager, new NtlmAuthenticationConverter());
        filter.setRequestMatcher(AnyRequestMatcher.INSTANCE);
        return filter;
    }

}
