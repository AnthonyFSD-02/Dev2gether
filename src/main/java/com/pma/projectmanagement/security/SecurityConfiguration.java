package com.pma.projectmanagement.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    DataSource dataSource;

    @Autowired
    BCryptPasswordEncoder bCryptEncoder;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
       auth.jdbcAuthentication()
               .usersByUsernameQuery("select username, password, enabled from user_accounts where username = ?")
               .authoritiesByUsernameQuery("select username, role from user_accounts where username = ?")
               .dataSource(dataSource)
               .passwordEncoder(bCryptEncoder);
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/projects/new").hasAuthority("ADMIN")
                .antMatchers("/projects/save").hasAuthority("ADMIN")
                .antMatchers("/", "/**").permitAll().and().formLogin();
                //.loginProcessingUrl("/")
                //ISSUE IS PASSWORD THE USER INPUTS ON CUSTOM LOGIN IS NOT CATCHING ENCRYPTION
//                .loginPage("/login")
//                .successForwardUrl("/")
//                .and().csrf().disable();
    }


//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .cors().and()
//                .csrf().disable().authorizeRequests()
//                .antMatchers("/users").hasRole("manager")
//                .anyRequest().authenticated()
//                .and()
//                .formLogin();
//                .authorizeRequests()
//                .antMatchers("/resources/**").permitAll()
//                .antMatchers("/login*").permitAll()
//                .anyRequest().authenticated()
//                .and().formLogin().loginPage("/login");
//    }
//    @Override
//    public void configure(WebSecurity web) {
//        web.ignoring().antMatchers("/resources/**");
//    }
//    @Autowired
//    private UserDetailsService userDetailsService;
//
//    @Autowired
//    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
//    BCryptPasswordEncoder pe = new  BCryptPasswordEncoder();
//    auth.userDetailsService(userDetailsService).passwordEncoder(pe);
//}



}