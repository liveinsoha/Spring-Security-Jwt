package spring.jwt.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.SecurityProperties;

import javax.xml.crypto.dsig.spec.XPathType;
import java.io.IOException;
import java.io.PrintWriter;

@Slf4j
public class MyFilter1 implements Filter {


    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        /**
         * 토큰: cos 이걸 만들어야 하는데, id, pw 정상적으로 들어와서 로그인이 완료되면 토큰을 만들고 그걸 응답해준다.
         * 요청할 때 마다 header에 Authorization에 value값으로 토큰을 가지고 온다
         * 그때 토큰이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지만 검증하면 된다 (RSA, HS256)
         */

        if (req.getMethod().equals("POST")) {
            log.info("POST 요청 됨");
            String headerAuth = req.getHeader("Authorization");
            log.info("headerAuth = " + headerAuth);

            /**
             *
             */
            if (headerAuth.equals("cos")) {
                log.info("인증 완료");
                chain.doFilter(req, res);
            } else {
                PrintWriter out = res.getWriter();
                out.println("인증 안 됨");
            }
        }
    }
}
