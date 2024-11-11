package jj.stella.config;

import java.security.Key;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import jj.stella.filter.auth.JwtAuthentication;
import jj.stella.filter.csrf.CsrfHandler;
import jj.stella.filter.csrf.CsrfRepository;
import jj.stella.properties.AuthProperties;
import jj.stella.repository.dao.MainDao;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
	private final AuthProperties authProperties;
	public SecurityConfig(AuthProperties authProperties) {
		this.authProperties = authProperties;
	};
	
	@Value("${server.url.refresh}")
	private String REFRESH_SERVER;
	
	private static final String[] WHITE_LIST = {
		"/resources/**", "/favicon.ico", "/"
	};
	
	// JwtAuthenticationFilter에 직접 추가하면
	// 생명주기 밖에서 생성되기 때문에 MainDao가 null로 초기화 됨. 
	@Autowired
	private MainDao mainDao;
	
	// JWT에 설정된 jti가 Redis에 존재하는지 판단
	@Autowired
	private RedisTemplate<String, String> redisTemplate;
	
	// Spring Security 접근권한 설정
	@Bean
	protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		
		String JWT_HEADER = authProperties.getJwt().getHeader();
		String JWT_KEY = authProperties.getJwt().getKey();
		String JWT_DECRYPT_SIGN = authProperties.getJwt().getDecrypt().getSign();
		String JWT_DECRYPT_TOKEN = authProperties.getJwt().getDecrypt().getToken();
		String JWT_DECRYPT_REFRESH_SIGN = authProperties.getJwt().getDecrypt().getRefresh().getSign();
		String JWT_DECRYPT_REFRESH_TOKEN = authProperties.getJwt().getDecrypt().getRefresh().getToken();
		
		String CSRF_NAME = authProperties.getCsrf().getName();
		String CSRF_PARAMETER = authProperties.getCsrf().getParameter();
		String CSRF_HEADER = authProperties.getCsrf().getHeader();
		
		return http
			.headers(headers ->
				headers
					.frameOptions(frame -> frame.sameOrigin()
			))
			.cors(cors -> corsConfigurationSource())
			.csrf(csrf ->
				csrf
					// XSRF-TOKEN 발급 ( 쿠키저장 )	
					.csrfTokenRepository(new CsrfRepository(CSRF_NAME, CSRF_PARAMETER, CSRF_HEADER))
					.csrfTokenRequestHandler(new CsrfHandler(CSRF_PARAMETER))
			)
			.formLogin(form ->
				form
					.loginPage("/")
			)
			.authorizeHttpRequests(auth ->
				auth
					// CorsUtil PreFlight 요청은 인증처리 하지 않겠다는 의미
					// CorsUtil PreFlight에는 Authorization 헤더를 줄 수 없으므로 401 응답을 해선안된다.
					.requestMatchers(CorsUtils::isPreFlightRequest).permitAll()
					.requestMatchers(getRequestMatchers(WHITE_LIST)).permitAll()
					.anyRequest().authenticated()
			)
			.addFilterBefore(new JwtAuthentication(
				JWT_HEADER, JWT_KEY,
				decryptSignKey(JWT_DECRYPT_SIGN), decryptTokenKey(JWT_DECRYPT_TOKEN),
				decryptTokenKey(JWT_DECRYPT_REFRESH_SIGN), decryptTokenKey(JWT_DECRYPT_REFRESH_TOKEN),
				REFRESH_SERVER, mainDao, redisTemplate
			), UsernamePasswordAuthenticationFilter.class)
			.build();
	};
	
	// 비밀번호 암호화 ( 단방향 복호화 불가능 )
	@Bean
	public PasswordEncoder encoder() {
		
		PasswordEncoder encoder = new BCryptPasswordEncoder();
		return encoder;
		
	};
	
	// CORS 정책 수립
	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		
		CorsConfiguration corsConfig = new CorsConfiguration();
		corsConfig.addAllowedOriginPattern("*://*.dev.st2lla.co.kr");
		corsConfig.addAllowedOriginPattern("*://*.intra.st2lla.co.kr");
		corsConfig.setAllowCredentials(true);
		corsConfig.setMaxAge(3600L);
		corsConfig.setAllowedMethods(Arrays.asList("GET"));
		
		corsConfig.setAllowedHeaders(
			Arrays.asList(
				"Content-Type",
				"X-XSRF-TOKEN",
				"Authorization",
				"User-Agent",
				"Content-Length",
				"X-Requested-With"
			)
		);
		
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", corsConfig);
		
		return source;
		
	};
	
	// 서명과 토큰의 복호화를 위한 Key 설정
	private Key decryptSignKey(String key) {
		
		// Base64 인코딩된 문자열을 디코드하여 바이트 배열로 변환
		byte[] decodedKey = Base64.getDecoder().decode(key);
		
		// 바이트 배열을 사용하여 SecretKey 객체 생성
		return new SecretKeySpec(decodedKey, 0, decodedKey.length, "HmacSHA256");
		
	};
	private Key decryptTokenKey(String key) {
		
		byte[] decodedKey = Base64.getDecoder().decode(key);
		return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
		
	};
	
	private RequestMatcher[] getRequestMatchers(String... str) {
		return Arrays.stream(str)
			.map(AntPathRequestMatcher::new)
			.toArray(RequestMatcher[]::new);
	};
	
}