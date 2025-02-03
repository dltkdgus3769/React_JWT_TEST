package com.busanit501.api5012.config;

import com.busanit501.api5012.security.APILoginSuccessHandler;
import com.busanit501.api5012.security.APIUserDetailsService;
import com.busanit501.api5012.security.filter.APILoginFilter;
import com.busanit501.api5012.util.JWTUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Log4j2
@Configuration
// 어노테이션을 이용해서, 특정 권한 있는 페이지 접근시, 구분가능.
//@EnableGlobalMethodSecurity(prePostEnabled = true)
// 위 어노테이션 지원중단, 아래 어노테이션 으로 교체, 기본으로 prePostEnabled = true ,
@EnableMethodSecurity
@EnableWebSecurity
@RequiredArgsConstructor
public class CustomSecurityConfig {

    private final APIUserDetailsService apiUserDetailsService;
    private final JWTUtil jwtUtil;

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        log.info("시큐리티 동작 확인 ====webSecurityCustomizer======================");
        return (web) ->
                web.ignoring()
                        .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        log.info("===========config=================");

        AuthenticationManagerBuilder authenticationManagerBuilder =
                http.getSharedObject(AuthenticationManagerBuilder.class);

        authenticationManagerBuilder
                .userDetailsService(apiUserDetailsService)
                .passwordEncoder(passwordEncoder());

        // Get AuthenticationManager 세팅1
        AuthenticationManager authenticationManager =
                authenticationManagerBuilder.build();

        //반드시 필요 세팅1
        http.authenticationManager(authenticationManager);

        //APILoginFilter 세팅1
        APILoginFilter apiLoginFilter = new APILoginFilter("/generateToken");
        apiLoginFilter.setAuthenticationManager(authenticationManager);

        // APILoginSuccessHandler 생성: 인증 성공 후 처리 로직을 담당
        APILoginSuccessHandler successHandler = new APILoginSuccessHandler(jwtUtil);

        // SuccessHandler 설정: 로그인 성공 시 APILoginSuccessHandler가 호출되도록 설정
        apiLoginFilter.setAuthenticationSuccessHandler(successHandler);
        //APILoginFilter의 위치 조정 세팅1, 사용자 인증 전에 ,
        http.addFilterBefore(apiLoginFilter, UsernamePasswordAuthenticationFilter.class);

        http.csrf(httpSecurityCsrfConfigurer -> httpSecurityCsrfConfigurer.disable());
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }


}