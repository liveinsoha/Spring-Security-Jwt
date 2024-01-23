package spring.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import spring.jwt.config.auth.PrincipalDetails;
import spring.jwt.dto.LoginRequestDto;

import java.io.IOException;
import java.util.Date;

//스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있는데
// login 요청해서 username, password전송하면 (postman)
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    //UsernamePasswordAuthenticationFilter는 AuthenticationManager을 통해서 로그인을 시도한다.


    // login요청을 하면 로그인 시도를 위해서 실행되는 함수이다.
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.info("JwtAuthenticationFilter : 로그인 시도중");

        ObjectMapper objectMapper = new ObjectMapper();
        LoginRequestDto loginRequestDto = null;
        try {
            loginRequestDto = objectMapper.readValue(request.getInputStream(), LoginRequestDto.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(loginRequestDto.getUsername(), loginRequestDto.getPassword());
        log.info("토큰 생성 완료");
        Authentication authentication = authenticationManager.authenticate(token);

        PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();
        log.info("principal.getUser().getUsername() = " + principal.getUser().getUsername());

        /**
         * authentication객체가 session영역에 저장을 해야하고 그 방법은 return하는 것이다
         * 리턴의 이유는 권한 관리를 스프링 시큐리티가 대신 해주기 때문에 편하려고 하는 것이다
         * 굳이 JWT토큰을 사용하면서 세션을 만들 이유가 없지만 , 단지 둰한 처리 때문에 session에 넣우줍니다
         */

        return authentication;
    }


    /**
     * successfulAuthentication실행 후 인증이 정상적으로 되었으면 succesfulAutehntication함수가 실행 된다.
     * JWT토큰을 만들어서 request요청한 사용자애게 JWT토큰을 response해주면 된다.
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        log.info("JwtAuthenticationFilter.successfulAuthentication");
        log.info("인증 완료");

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        String jwtToken = JWT.create()
                .withSubject("cos토큰")
                .withExpiresAt(new Date(System.currentTimeMillis() + (JwtProperties.EXPIRATION_TIME)))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));

        response.addHeader("Authorization",JwtProperties.TOKEN_PREFIX + jwtToken);
        log.info("헤더에 토큰 부여");
    }

    //
}
