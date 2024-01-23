jwt = json web token의 약자이다
jwt가 왜 사용되고 어디에 쓰이는 지 알아보자


Session
인증의 경우 기본적으로 세션을 사용하는데 세션에는 문제점이 있다.
동접자가 많은 경우 서버를 분산하여 로드 밸런싱 처리를 하는데, 이때 세션을 처리하기 위한 비용이 발생하기 때문이다.
하드디스크에 세션 정보를 저장하게 되면 I/O가 발생하여 현저히 느려진다.

TCP

응용계층 : 프로그램(lol)
프리젠테이션 : 암호화, 압축
세션계층 : 인증 체크
트랜스포트 : TCP / UDP
네트워크 :
데이터링크 :
물리 :

TCP는 신뢰성이 있는 통신이다. 잘 전달 되었는지 반응(ACK)을 확인한다.(웹)
UDP는 신뢰성이 없다. 보내고 끝이고 주로 사람이 이해할 수 있는 컨텐츠 전송에 쓰인다 (전화, 동영상)


CIA
기밀성, 무결성, 가용성

1. 열쇠 전달의 문제
2. 누구로 부터 왔는지  
3. -> 보안 해결할 수 있다
RSA(암호화)
public Key : 공용키
Private Key : 개인키

A 
공개키
B의 공개키로 암호화하고 A의 개인키로 포장해서 보낸다.

공개키로 암호화 한 건 개인키로 열 수 있다.
개인키로 암호화 한 건 공개키로 열 수 있다.

1. 문서를 받는다
2. A의 공개키로 열어본다 
  - 열리면 인증(o)
  - 안 열리면 인증(x)
3. B의 개인키로 열어본다
  - 암호화한 내용을 볼 수 있다  


헤더

페이로드

서명

서버는 전달받은 jwt에서 헤더와 페이로드를 전달받아 자신이 가진 비밀키(cos)와 결합하여 HMACSHA256으로 암호화를 해보고
jwt의 signature와 같다면 이 요청이 자신의 서버에서 인증된 요청인지를 판단할 수 있다


JWT는 "JSON Web Token"의 약자로, 웹 표준으로서 데이터를 안전하게 전달하기 위한 간단한 방법을 제공하는 토큰 기반의 인증 방식입니다. JWT는 일반적으로 클라이언트와 서버 간의 정보를 안전하게 전송하기 위해 사용되며, 웹 애플리케이션에서 사용자의 인증 및 권한 부여를 처리하는 데 널리 활용됩니다.

JWT는 세 부분으로 구성되어 있습니다: Header, Payload, Signature.

Header (헤더):
JWT의 헤더는 두 가지 정보를 포함하고 있습니다. 첫 번째는 토큰의 타입을 나타내는 "typ" 필드이고, 두 번째는 사용된 해싱 알고리즘을 나타내는 "alg" 필드입니다. 이 헤더는 Base64로 인코딩되어 있습니다.

Payload (페이로드):
페이로드는 클레임(claim)이라 불리는 데이터를 포함하고 있습니다. 클레임은 사용자에 대한 정보와 관련된 추가적인 데이터를 제공합니다. 클레임은 세 가지 유형으로 나뉩니다: 등록된 클레임, 공개 클레임, 비공개 클레임. 마찬가지로 페이로드는 Base64로 인코딩되어 있습니다.

Signature (서명):
서명은 헤더와 페이로드의 내용을 기반으로 생성되며, 비밀 키를 사용하여 생성됩니다. 서명은 토큰이 변경되지 않았음을 검증하는 데 사용됩니다.

JWT의 일반적인 사용 사례는 다음과 같습니다:

인증 및 권한 부여: 사용자가 로그인하면 서버는 JWT를 발급하고, 클라이언트는 이 토큰을 저장하고 나중에 서버에 전달하여 자원에 대한 액세스를 얻습니다.
정보 교환: JWT는 정보를 안전하게 전송하는 데 사용될 수 있습니다. 예를 들어, 두 서버 간에 안전한 방식으로 정보를 공유하는 데 활용될 수 있습니다.
JWT는 간단하면서도 유연하며, 많은 웹 애플리케이션에서 사용되고 있습니다. 그러나 주의할 점은 서버가 JWT를 안전하게 관리하고 검증해야 하며, 중요한 정보를 포함하는 경우에는 HTTPS와 함께 사용해야 합니다.


JWT(Jason Web Token)와 세션(Session)은 둘 다 인증(Authentication)과 관련된 웹 애플리케이션에서 사용되는 방법이지만, 각각의 특징과 작동 방식은 다릅니다.

JWT (JSON Web Token):
토큰 기반 인증:

JWT는 클라이언트와 서버 간의 인증을 토큰을 사용하여 처리합니다. 사용자가 로그인하면 서버는 JWT를 생성하고, 이를 클라이언트에게 전달합니다.
클라이언트는 이 토큰을 저장하고, 나중에 요청할 때 HTTP 헤더에 포함하여 서버에 전송합니다.
서버는 토큰을 검증하고, 필요한 권한이 부여된 경우에 요청을 처리합니다.
Self-contained (자체 포함성):

JWT는 헤더, 페이로드, 서명으로 구성되어 있으며, 이들을 Base64로 인코딩하여 하나의 문자열로 만듭니다.
토큰에는 클레임(claim)이라 불리는 정보들이 포함되어 있으며, 이는 사용자의 ID, 권한, 만료 시간 등을 나타냅니다.
Stateless (무상태성):

서버는 토큰을 검증하기 위해 내부적으로 필요한 정보를 포함하고 있으므로, 상태를 서버에 저장할 필요가 없습니다.
이는 서버의 확장성을 높이는 데 도움이 됩니다.
세션:
서버 측 저장:

세션은 서버 측에서 상태 정보를 저장하는 방식입니다. 사용자가 로그인하면 서버는 세션을 생성하고, 클라이언트에게 세션 ID를 제공합니다.
클라이언트는 이 세션 ID를 쿠키 또는 URL 매개변수 등을 통해 저장하고, 서버에 요청할 때마다 세션 ID를 함께 전송합니다.
유지 기간:

세션은 특정 시간 동안 유지됩니다. 사용자가 일정 시간 동안 활동이 없으면 세션이 만료될 수 있습니다.
세션의 만료 기간은 서버 측에서 설정하며, 보통은 일정 시간이 지나면 세션을 종료하도록 구성됩니다.
서버 상태 유지:

서버는 세션을 통해 사용자의 상태를 유지하고, 이를 통해 사용자의 로그인 상태 및 권한 등을 파악합니다.
세션은 서버 측에서 유지되므로 서버에 저장 공간이 필요합니다.
선택 사항:
JWT는 무상태적이고 클라이언트 측에서 상태를 유지하므로, 서버 확장성이 높아집니다. 그러나 보안적인 측면에서 서버에서 토큰을 검증하기 때문에 안전성을 고려해야 합니다.
세션은 서버 측에서 상태를 유지하므로, 서버에 부담을 줄 수 있지만, 세션 자체가 서버에 의해 안전하게 유지되기 때문에 일반적으로 안전성이 높습니다.
어떤 방식을 선택할지는 애플리케이션의 요구 사항과 보안 정책에 따라 다릅니다. 일부 애플리케이션은 JWT를 사용하여 무상태적이고 확장 가능한 인증을 선호하고, 다른 애플리케이션은 세션을 사용하여 서버 측에서 상태를 유지하고 보안성을 강화하는 것을 선호할 수 있습니다.

# 구현 프로세스
필터를 등록하는데, 빈 등록으로 순서를 설정할 수 있지만 이렇게 등록된 필터들은 모드 시큐리티 필터 이후에 거치게 된다.
시큐리티 필터보다 앞서서 필터를 거치게 하고 싶으면 securityConfig에서 http.addFilterBefore메소드를 사용하면 된다.

````agsl
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(CsrfConfigurer::disable)
                .addFilterBefore(new MyFilter1(), SecurityContextHolderFilter.class)
                .sessionManagement(sessionManagementConfigurer -> sessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))//세션 안쓴다
                .addFilter(corsFilter) //모든 요청은 이 필터를 거친다
                .formLogin(AbstractHttpConfigurer::disable) //폼 로그인 안쓴다..?
                .httpBasic(AbstractHttpConfigurer::disable) //기본적인 http로그인 방식도 쓰지 않는다.
                .authorizeHttpRequests(authorize ->
                        authorize.requestMatchers("/api/v1/user/**").hasAnyRole("USER", "ADMIN", "MANAGER")
                                .requestMatchers("/api/v1/admin/**").hasAnyRole("ADMIN")
                                .requestMatchers("/api/v1/manager/**").hasAnyRole("ADMIN", "MANAGER")
                                .anyRequest().permitAll());

        return http.build();
````

- 시큐리티 필터를 거치기 전에 걸러내기 위해서 시큐리티 필터 앞에 MyFilter를 설치한다.
- 마이필터에서 토큰 인증이 된다면 스플이 시큐리티 프로세스를 거친다. UserDetailsService -> UserDetails 객체 생성하여 리턴.
설정 한 후에 postman으로 localhost:8080/login으로 바디에 username : aaa , password : 123을 작성해서 보내면 404에러가 뜬다.
- 현재 formLogin.disable 되어 있기 떄문에 해당 경로(localhost:8080/login) 에서 동작하지 않는다.

UsernamePasswordAuthenticationFilter을 구현한 필터를 하나 만들고 필터를 등록해줘야 한다.

````agsl
 @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);

        http.csrf(CsrfConfigurer::disable)
                .addFilterBefore(new MyFilter1(), SecurityContextHolderFilter.class)
                .sessionManagement(sessionManagementConfigurer -> sessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))//세션 안쓴다
                .addFilter(corsFilter) //모든 요청은 이 필터를 거친다
                .formLogin(AbstractHttpConfigurer::disable) //폼 로그인 안쓴다..?
                .httpBasic(AbstractHttpConfigurer::disable) //기본적인 http로그인 방식도 쓰지 않는다..
                .addFilter(new JwtAuthenticationFilter(authenticationManager)) // UsernamePasswordAuthenticationFilter을 구현한 JwtAuthenticationFilter 필터 등록
                .authorizeHttpRequests(authorize ->
                authorize.requestMatchers("/api/v1/user/**").hasAnyRole("USER", "ADMIN", "MANAGER")
                        .requestMatchers("/api/v1/admin/**").hasAnyRole("ADMIN")
                        .requestMatchers("/api/v1/manager/**").hasAnyRole("ADMIN", "MANAGER")
                        .anyRequest().permitAll());

        return http.build();
    }
````

필터를 구현하고 등록을 마치면 localhost:8080/login 경로로 들어왔을 때 다음 attemptAuthentication 메소드가 실행된다

````agsl
 @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter : 로그인 시도중");
        
        //1.username, password를 받아서
        //2.정상인지 로그인 시도를 해본다. authenticationManager로 로그인 시도를 하면
      //3. PrincipalDetatilsService가 호출 loadUserByUSername() 메서드가 실행된다
        
        //4.PrincipalDetaitls를 세션에 담고 -> 세션에 담지 않을 경우 ROLE권한 관리가 되지 않는다.(스프링 시큐리티는 PrincipalDetails를 가지고 권환관리를 하기 때문이다.)
         //5.JWT토큰을 만들어서 응답해주면 된다.
        return super.attemptAuthentication(request, response);
    }
````


````agsl
  @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter : 로그인 시도중");

        ObjectMapper objectMapper = new ObjectMapper();
        LoginRequestDto loginRequestDto = null;
        try {
            loginRequestDto = objectMapper.readValue(request.getInputStream(), LoginRequestDto.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(loginRequestDto.getUsername(), loginRequestDto.getPassword());

        //토큰을 생성하고 로그인 시도를 한다.
        //PrincipalDetailsService의 loadUserByusername() 함수가 실행된다
        Authentication authentication = authenticationManager.authenticate(token);
        //인증이 되면 authentication객체에는 PrincipalDetails에 내가 로그인한 정보가 담겨있다.
        //인증이 정상적으로 되면 authentication객체가 session영역에 저장된다. => principal객체가 담겨있으면 정상적으로 로그인이 처리되었다는 이야기이다
        PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("principal.getUser().getUsername() = " + principal.getUser().getUsername());

        return super.attemptAuthentication(request, response);
    }
````

- 로그인 시도를 하기 위해서 토큰을 생성하야 한다. 원래 formLogin의 경우 스프링 시큐리티가 해주는데 disable했기 때문에 우리가 구현해야 한다.
- 토큰을 생성하고 로그인 시도를 한다.


리팩토링 하였다.
````agsl
public class SecurityConfig {

    @Autowired
    private CorsConfig corsConfig;


    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.csrf(CsrfConfigurer::disable)
                .addFilterBefore(new MyFilter1(), SecurityContextHolderFilter.class)
                .sessionManagement(sessionManagementConfigurer -> sessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))//세션 안쓴다
                //.addFilter(corsFilter) //모든 요청은 이 필터를 거친다
                .formLogin(AbstractHttpConfigurer::disable) //폼 로그인 안쓴다..?
                .httpBasic(AbstractHttpConfigurer::disable) //기본적인 http로그인 방식도 쓰지 않는다..
                // .addFilter(new JwtAuthenticationFilter(authenticationManager)) // UsernamePasswordAuthenticationFilter을 구현한 JwtAuthenticationFilter 필터 등록
                .with(new MyCustomDsl(), myCustomDsl ->myCustomDsl.flag(true));
        http
                .authorizeHttpRequests(authorize ->
                        authorize.requestMatchers("/api/v1/user/**").hasAnyRole("USER", "ADMIN", "MANAGER")
                                .requestMatchers("/api/v1/admin/**").hasAnyRole("ADMIN")
                                .requestMatchers("/api/v1/manager/**").hasAnyRole("ADMIN", "MANAGER")
                                .anyRequest().permitAll());

        return http.build();
    }

    class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> {

        private boolean flag;

        @Override
        public void configure(HttpSecurity http) throws Exception {
            AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
            http
                    .addFilter(corsConfig.corsFilter())
                    .addFilter(new JwtAuthenticationFilter(authenticationManager));
            // .addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository));
        }


        public MyCustomDsl flag(boolean value) {
            this.flag = value;
            return this;
        }
    }

````

````agsl
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("JwtAuthenticationFilter.successfulAuthentication");
        super.successfulAuthentication(request, response, chain, authResult);
    }

````
- successfulAuthentication실행 후 인증이 정상적으로 되었으면 succesfulAutehntication함수가 실행 된다.
- JWT토큰을 만들어서 request요청한 사용자애게 JWT토큰을 response해주면 된다.

````agsl
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("JwtAuthenticationFilter.successfulAuthentication");
        System.out.println("인증 완료");

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        String jwtToken = JWT.create()
                .withSubject("cos토큰")
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10)))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos"));

        response.addHeader("Authorization","Bearer " + jwtToken);
    }
````

- 세션 방식
 유저네임, 패스워드 로그인 정상 -> 서버쪽 세션Id생성 -> 클라이언트 쿠키 세션Id를 응답 
 -> 요청할 때마다 쿠키값 세션Id를 항상 들고 서버쪽으로 요청하기 떄문에 서버는 세션Id가 유효한지 판단해서 유효하면 인증이 필요한 페이지르 접근하게 하면 된다.

- JWT방식
 유저네임, 패스워드 로그인 정상 -> JWT토큰을 생성 -> 클라이언트 쪽으로 JWT토큰을 응답
 -> 요청할 때마다 JWT토큰을 가지고 요청, 서버는 JWT토큰이 유효한지를 판단(판단하는 필터를 만들어야 한다.)


````agsl
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

        String token = jwtToken.replace("Bearer ", "");
        log.info("token = {}", token);

        String username = JWT.require(Algorithm.HMAC512("cos")).build().verify(token).getClaim("username").asString();
        if (username != null) {
            User userEntity = userRepository.findByUsername(username);
            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
            Authentication authentication
                    = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.info("권한 인증 완료");
        }

        chain.doFilter(request, response);

    }
}
````

- 토큰을 받아 prefix를 떼고 토큰을 다시 디코딩한 다음 정상적인 토큰인지 확인한다. username을 얻고, 리포지토리에 있는 회원이라면,
- 


