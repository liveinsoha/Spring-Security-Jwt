package spring.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import spring.jwt.config.auth.PrincipalDetails;
import spring.jwt.domain.User;
import spring.jwt.repository.UserRepository;

import java.io.IOException;

@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        //   log.info("인증이나 권한이 필요한 주소 요청");

        //헤더로부터 JWT토큰을 받아 검증을 해서 정상적인 사용자인지 확인.
        String jwtToken = request.getHeader("Authorization");
        log.info("jwtToken = " + jwtToken);

        if (jwtToken == null || !jwtToken.startsWith("Bearer")) {
            log.info("권한 없음");
            chain.doFilter(request, response);
            return;
        }

        String token = jwtToken.replace(JwtProperties.TOKEN_PREFIX, "");
        log.info("token = {}", token);

        String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(token).getClaim("username").asString();
        if (username != null) {
            User userEntity = userRepository.findByUsername(username);

            // 인증은 토큰 검증시 끝. 인증을 하기 위해서가 아닌 스프링 시큐리티가 수행해주는 권한 처리를 위해
            // 아래와 같이 토큰을 만들어서 Authentication 객체를 강제로 만들고 그걸 세션에 저장!
            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
            Authentication authentication
                    = new UsernamePasswordAuthenticationToken(
                    principalDetails, // 나중에 컨트롤러에서 DI해서 쓸 때 사용하기 편함.
                    null,
                    principalDetails.getAuthorities());

            /**
             * 그러나 STATELESS 상태에서는 기존 로그인 이후 해당정보를 서버에서 관리 하지 않기에
             * /login 경로를 통해 로그인 이후 권한이 필요한 페이지인 /hello2 를 호출하면   403 에러가 발생한다.
             * ( SecurityContextHolder.getContext().getAuthentication() 정보가 null 로 되어 있음 기존 정보를 가지고 있지 않음 )
             */
            //권한 관리를 위해 Authentication객체를 강제로 시큐리티의 세션에 접근하여 값 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.info("권한 인증 완료");
        }

        chain.doFilter(request, response);

    }
}
