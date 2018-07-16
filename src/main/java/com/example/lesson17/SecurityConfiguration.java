package com.example.lesson17;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/admin").access("hasAuthority('ROLE_ADMIN')")

                .anyRequest().authenticated()
                .and()

                .formLogin().loginPage("/login").permitAll()// added by lesson 18 // //*** creating a login form ***//

                .and()
                .httpBasic(); //*** user can avoid a login promt by putting login details in the request ***//
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) // ** override the defult configure method, configure user who can access the application**//
            throws Exception {
        auth.inMemoryAuthentication().
                withUser("admin").password("admin").roles("ADMIN")
                .and()
                .withUser("user").password("password").roles("USER");

    }

    @SuppressWarnings("deprecation")
    @Bean
    public static NoOpPasswordEncoder passwordEncoder() {
        return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
    }
}