package com.springboot.config;

import com.springboot.auth.filter.JwtAuthenticationFilter;
import com.springboot.auth.jwt.JwtTokenizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
public class SecurityConfiguration {
    //JwtAuthenticationFilter에서 사용되기에 DI
    private final JwtTokenizer jwtTokenizer;

    public SecurityConfiguration(JwtTokenizer jwtTokenizer) {
        this.jwtTokenizer = jwtTokenizer;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                //H2 웹 콘솔을 사용하기 위해 추가
                .headers().frameOptions().sameOrigin()
                .and()
                //csrf공격 보안설정 비활성화 (설정하지 않으면 403에러)
                .csrf().disable()
                //CorsConfigurationSource Bean을 제공하여 CorsFilter를 적용함으로써 CORS를 처리
                .cors(Customizer.withDefaults())
                //폼 로그인과 http basic 인증방식 비활성화
                .formLogin().disable()
                .httpBasic().disable()
                .apply(new CustomFilterConfigurer())
                .and()
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().permitAll());
        return http.build();
    }

    //passwordEncoder Bean 객체 생성
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    //CORS 기본설정
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        //모든 출처에 대해 스크립트 기반의 HTTP 통신을 허용
        configuration.setAllowedOrigins(Arrays.asList("*"));
        //파라미터로 지정한 HTTP Method에 대한 통신을 허용
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PATCH", "DELETE"));

        // CorsConfigurationSource 인터페이스의 구현체 UrlBasedCorsConfigurationSource 객체를 생성
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        //모든 URL에 지금까지 구성한 CORS 정책을 적용한다.
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

    //Custom Configurer : Spring Security의 Configuratuon를 개발자가 정의한 클래스
    //JwtAuthenticationFilter를 등록하는 역할
    //AbstractHttpConfigurer<AbstractHttpConfigurer를 상속하는 타입, HttpSecurityBuilder를 상속하는 타입>
    public class CustomFilterConfigurer extends AbstractHttpConfigurer<CustomFilterConfigurer, HttpSecurity>{
        //Configuration 커스터마이징
        @Override
        public void configure(HttpSecurity builder) throws Exception {
            //AuthenticationManager 객체를 생성
            //getSharedObject 메서드를 통해 Spring Security의 설정을 구성하는 SecurityConfigurer간에 공유되는 객체를 얻을 수 있다.
            AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);

            //JwtAuthenticationFilter를 생성하면서 필요한 인자를 Di해준다.
            JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(authenticationManager, jwtTokenizer);  // (2-4)
            //디폴트 request URL를 /login -> /v11/auth/login으로 변경
            jwtAuthenticationFilter.setFilterProcessesUrl("/v11/auth/login");

            //JwtAuthenticationFilter를 Spring Security Filter Chain에 추가한다.
            builder.addFilter(jwtAuthenticationFilter);
        }
    }
}