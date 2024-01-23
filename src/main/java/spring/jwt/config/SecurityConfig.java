package spring.jwt.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import spring.jwt.config.jwt.JwtAuthorizationFilter;
import spring.jwt.filter.MyFilter1;
import spring.jwt.config.jwt.JwtAuthenticationFilter;
import spring.jwt.repository.UserRepository;

@Configuration
@EnableWebSecurity

public class SecurityConfig {

    @Autowired
    private CorsConfig corsConfig;

    @Autowired
    private UserRepository userRepository;


    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.csrf(CsrfConfigurer::disable)
                //.addFilterBefore(new MyFilter1(), SecurityContextHolderFilter.class)
                .sessionManagement(sessionManagementConfigurer -> sessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))//세션 안쓴다
                //.addFilter(corsFilter) //모든 요청은 이 필터를 거친다
                .formLogin(AbstractHttpConfigurer::disable) //폼 로그인 안쓴다..?
                .httpBasic(AbstractHttpConfigurer::disable) //기본적인 http로그인 방식도 쓰지 않는다..
                // .addFilter(new JwtAuthenticationFilter(authenticationManager)) // UsernamePasswordAuthenticationFilter을 구현한 JwtAuthenticationFilter 필터 등록
                .authorizeHttpRequests(authorize ->
                        authorize.requestMatchers("/api/v1/user/**").hasAnyRole("USER", "ADMIN", "MANAGER")
                                .requestMatchers("/api/v1/admin/**").hasAnyRole("ADMIN")
                                .requestMatchers("/api/v1/manager/**").hasAnyRole("ADMIN", "MANAGER")
                                .anyRequest().permitAll())
                .with(new MyCustomDsl(), myCustomDsl -> myCustomDsl.flag(true));

        return http.build();
    }

    class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> {

        private boolean flag;

        @Override
        public void configure(HttpSecurity http) throws Exception {
            AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
            http
                    .addFilter(corsConfig.corsFilter())
                    .addFilter(new JwtAuthenticationFilter(authenticationManager))
                    .addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository));

            // .addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository));
        }


        public MyCustomDsl flag(boolean value) {
            this.flag = value;
            return this;
        }
    }

    /**
     * httpBaisc이란 기본적으로 Id, Password를 가지고 Authorization 키에 담아서 요청하는 것.
     * 이떄 Id, Pw는 암호화 되지 않아서 보안에 취약 -> https를 써야한다.
     *
     * 우리가 사용할 방식은 Authorization : 토큰을 담아서 요청한다.
     * 토큰을 달고 요청하는 방식 -> Bearer방식. 노출이 되어도 비교적 아전하다.
     * Token은 Id, Pw로 요청을 할 때마다 발급한다.(만료시간이 있다.) 토큰에 Json Web Token방식을 적용할 것이다.
     */
}

