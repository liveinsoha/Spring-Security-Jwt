package spring.jwt.controller;


import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import spring.jwt.domain.User;
import spring.jwt.repository.UserRepository;

@RestController
@Slf4j
public class ApiController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private BCryptPasswordEncoder encoder;


    @GetMapping("/home")
    public String home() {
        return "<h1>home<h1/>";
    }

    @PostMapping("/token")
    public String token() {
        return "<h1>token<h1/>";
    }

    @PostMapping("/join")
    public String join(@RequestBody User user) {
        String encoded = encoder.encode(user.getPassword());
        user.setPassword(encoded);
        user.setRoles("ROLE_USER");
        userRepository.save(user);
        return " 회원가입 완료";
    }

    @RequestMapping("/api/v1/user")
    public String user(Authentication authentication) {
        log.info("authentication.getPrincipal() = {}", authentication.getPrincipal());
        return "user";
    }

    @RequestMapping("/api/v1/admin")
    public String admin(Authentication authentication) {
        log.info("authentication.getPrincipal() = {}", authentication.getPrincipal());
        return "admin";
    }

    @RequestMapping("/api/v1/manager")
    public String manager(Authentication authentication) {
        log.info("authentication.getPrincipal() = {}", authentication.getPrincipal());
        return "manager";
    }
}
