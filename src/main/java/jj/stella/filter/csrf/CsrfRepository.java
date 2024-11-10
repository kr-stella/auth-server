package jj.stella.filter.csrf;

import java.util.UUID;
import java.util.function.Consumer;

import org.springframework.http.ResponseCookie;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.WebUtils;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class CsrfRepository implements CsrfTokenRepository {
	
	/** CSRF 쿠키, 파라미터, 헤더 이름의 기본값 */
	/** CSRF 토큰 관련 설정 변수들 */
	private String CSRF_NAME;		// XSRF-TOKEN
	private String CSRF_PARAMETER;	// _csrf
	private String CSRF_HEADER;		// X-XSRF-TOKEN
	
	/**
	 * HttpServletRequest에서
	 * CSRF 토큰을 가져오거나 저장할 때 참조되는 키로 사용
	 * ( e.g )
	 * CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
	 * */
	private static final String CSRF_ATTRIBUTE_NAME = CsrfRepository.class.getName().concat(".REMOVED");
	
	/**
	 * HttpOnly 설정 / 기본값은 true
	 * 이걸 false로 바꾸거나 public CsrfCustomRepository() 에서
	 * 초기값을 false로 바꾸면
	 * CookieCsrfTokenRepository.withHttpOnlyFalse() 이거랑 똑같음
	 * */
	private boolean cookieHttpOnly = true;
	/** 쿠키 경로 */
	private String cookiePath;
	/** 쿠키 도메인 */
	private String cookieDomain;
	/** 쿠키 보안 설정 */
	private Boolean secure;
	/** 쿠키 최대 유효 기간 */
	private int cookieMaxAge = -1;
	
	/** 필요한 초기화 로직은 여기에 */
	public CsrfRepository(String CSRF_NAME, String CSRF_PARAMETER, String CSRF_HEADER) {
		
		this.cookieHttpOnly = false;
		this.secure = false;
		
		this.CSRF_NAME = CSRF_NAME;
		this.CSRF_PARAMETER = CSRF_PARAMETER;
		this.CSRF_HEADER = CSRF_HEADER;
		
	};
	
	/** CSRF 토큰 생성 */
	@Override
	public CsrfToken generateToken(HttpServletRequest req) {
		return new DefaultCsrfToken(this.CSRF_HEADER, this.CSRF_PARAMETER, createNewToken());
	};
	
	/** CSRF 토큰을 쿠키에 저장 or 제거 */
	@Override
	public void saveToken(CsrfToken csrf, HttpServletRequest req, HttpServletResponse res) {
		
		String token = (csrf != null)? csrf.getToken():"";
		ResponseCookie.ResponseCookieBuilder builder = ResponseCookie.from(this.CSRF_NAME, token)
			.secure((this.secure != null)?
				this.secure:req.isSecure()
			)
			.path(StringUtils.hasLength(this.cookiePath)?
				this.cookiePath:getRequestContext(req)
			)
			.maxAge((csrf != null)?
				this.cookieMaxAge:0
			)
			.httpOnly(this.cookieHttpOnly)
			.domain(this.cookieDomain);
		
		this.cookieCustomizer.accept(builder);
		Cookie cookie = createCookie(builder.build());
		res.addCookie(cookie);
		
		// 토큰값 유무에 따라 없으면 요청속성을 조절
		// 없으면 ("_csrf", TRUE) 설정 
		// 있으면 "_csrf" 삭제
		if(!StringUtils.hasLength(token))
			req.setAttribute(CSRF_ATTRIBUTE_NAME, Boolean.TRUE);
		else req.removeAttribute(CSRF_ATTRIBUTE_NAME);
		
		// 사용자 정의 로직 추가는 여기에
		// 유효성 검사를 위해 세션에 CSRF 토큰을 저장
		if(csrf != null) {
			req.getSession().setAttribute(this.CSRF_NAME, csrf.getToken());
		} else {
			req.getSession().removeAttribute(this.CSRF_NAME);
		}
		
	};
	
	/**
	 * CSRF 토큰 로드
	 * #1. CsrfFilter에서 doFilterInternal에서 loadDeferredToken 로직 실행
	 * #2. 1번은 실질적으로 CsrfTokenRepository의 loadDeferredToken을 실행
	 * #3. 결론적으로 DeferredCsrfToken 객체를 반환하는데 얘가 필요에 따라 CsrfToken을 조회 or 생성
	 * #4. DeferredCsrfToken.get() 로직이 실행되면, RepositoryDeferredCsrfToken.get() 로직이 실행
	 * #5. init();에 보면 csrfToken이 있는경우 바로 빠져나오고, return csrfToken이 이뤄짐.
	 * #6. init();에 보면 csrfToken이 없는경우
	 * - csrfToken이 없을때 generateToken, saveToken을 실행하는 로직이 실행
	 * 
	 * #7. equalsConstantTime는 CsrfToken이 존재하지 않거나 값이 null인경우 false를 반환함
	 * #8. 5번은 Invalid CSRF Token found for << 내가 자주본 에러
	 * 
	 * ### null이 반한되지 않고 있는경우는 DefaultCsrfToken으로 CsrfToken을 세팅함.
	 * 즉, 정상적이라면 RepositoryDeferredCsrfToken의 init() 로직에서
	 * this.rcsrfToken != null 이후 즉시 return을 담당.
	 * */
	// loadDelferredToken
	@Override
	public CsrfToken loadToken(HttpServletRequest req) {
		
		// 쿠키에 있는 XSRF-TOKEN을 조회
		Cookie cookie = WebUtils.getCookie(req, this.CSRF_NAME);
		
		// 쿠키에 XSRF-TOKEN자체가 없거나 XSRF-TOKEN의 값이 없는 경우 NULL 반환
		if(cookie == null || !StringUtils.hasLength(cookie.getValue()))
			return null;
		
		// 세션에 저장된 토큰과 비교
		// 이게 일치하면 유효한 토큰을 반환
		String token = (String) req.getSession().getAttribute(this.CSRF_NAME);
		if(token != null && token.equals(cookie.getValue()))
			return new DefaultCsrfToken(this.CSRF_HEADER, this.CSRF_PARAMETER, cookie.getValue());
		
		// 위 경우를 제외한 모든 경우에 NULL 반환
		return null;
		
//		// Boolean.TRUE와 일치하면 NULL 반환
//		if(Boolean.TRUE.equals(req.getAttribute(CSRF_ATTRIBUTE_NAME)))
//			return null;
//		
//		// 쿠키에서 XSRF-TOKEN 없으면 NULL 반환
//		Cookie cookie = WebUtils.getCookie(req, this.CSRF_NAME);
//		if(cookie == null)
//			return null;
//		
//		// 쿠키에서 XSRF-TOKEN의 값( token )이 없으면 NULL 반환
//		String token = cookie.getValue();
//		if(!StringUtils.hasLength(token))
//			return null;
//		
////		// 유효성 검사
////		String validate = (String) req.getSession().getAttribute(CSRF_ATTRIBUTE_NAME);
////		
////		System.out.println("validate ====> req.getSession().getAttribute(CSRF_HEADER_NAME) ====> " + req.getSession().getAttribute(CSRF_ATTRIBUTE_NAME));
////		System.out.println("validate ====> req.getSession().getAttribute(CSRF_HEADER_NAME) ====> " + req.getSession().getAttribute(CSRF_HEADER_NAME));
////		System.out.println("validate ====> req.getSession().getAttribute(CSRF_PARAMETER_NAME) ====> " + req.getSession().getAttribute(CSRF_PARAMETER_NAME));
////		
////		System.out.println("validate ====> cookie token value ====> " + token);
////		if(validate != null && validate.equals(token))
////			return new DefaultCsrfToken(this.CSRF_HEADER, this.CSRF_PARAMETER, token);
////		
//		// 유효한 토큰을 반환
//		return new DefaultCsrfToken(this.CSRF_HEADER, this.CSRF_PARAMETER, token);
		
	}
	
	/** CSRF 토큰을 생성하는 메소드 */
	private String createNewToken() {
		return UUID.randomUUID().toString();
	};
	
	/** ResponseCookie를 일반 Cookie객체로 변환하는 메소드 */
	private Cookie createCookie(ResponseCookie responseCookie) {
		
		Cookie cookie = new Cookie(responseCookie.getName(), responseCookie.getValue());
		cookie.setSecure(responseCookie.isSecure());
		cookie.setPath(responseCookie.getPath());
		cookie.setMaxAge((int) responseCookie.getMaxAge().getSeconds());
		cookie.setHttpOnly(responseCookie.isHttpOnly());
		
		if(StringUtils.hasLength(responseCookie.getDomain()))
			cookie.setDomain(responseCookie.getDomain());
		
		if(StringUtils.hasText(responseCookie.getSameSite()))
			cookie.setAttribute("SameSite", responseCookie.getSameSite());
		
		return cookie;
		
	};
	
	/**
	 * Getter, Setter 메소드들
	 * 설정을 변경하는 메소드들은 CSRF 보호 매커니즘의 세부 사항을 조정할 수 있게 해준다.
	 * */
	/** 요청으로부터 콘텍스트 경로를 가져오는 메소드 */
	private String getRequestContext(HttpServletRequest req) {
		String contextPath = req.getContextPath();
		return (contextPath.length() > 0)? contextPath:"/";
	};
	/**
	 * CSRF 쿠키의 경로를 설정
	 * @param path the path to use
	 * */
	public void setCookiePath(String path) {
		this.cookiePath = path;
	};
	/**
	 * CSRF 쿠키 경로 호출
	 * @return the path to be used.
	 * */
	public String getCookiePath() {
		return this.cookiePath;
	};
	
	public void setParameterName(String CSRF_PARAMETER) {
		Assert.notNull(CSRF_PARAMETER, "CSRF_PARAMETER cannot be null");
		this.CSRF_PARAMETER = CSRF_PARAMETER;
	};
	public void setHeaderName(String CSRF_HEADER) {
		Assert.notNull(CSRF_HEADER, "CSRF_HEADER cannot be null");
		this.CSRF_HEADER = CSRF_HEADER;
	};
	public void setCookieName(String CSRF_NAME) {
		Assert.notNull(CSRF_NAME, "CSRF_NAME cannot be null");
		this.CSRF_NAME = CSRF_NAME;
	};
	
	/**
	 * 쿠키 커스터마이저 ( 초기 아무것도 세팅 x )
	 * SecurityConfig에서 적용하려면 이렇게 작성해야 함.
	 * 
	 * ...
	 * .csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository))
	 * ...
	 * 
	 * Bean 등록
	 * private CsrfCustomRepository csrfTokenRepository() {
	 * 		CsrfCustomRepository repo = new CsrfCustomRepository();
	 * 		repo.setCookieCustomizer(builder -> {
	 * 			builder.path("/")
	 * 				.secure(true)
	 * 				.httpOnly(false)
	 * 				.domain("abcde")
	 * 				.maxAge(3600);
	 * 		});
	 * 		return repo;
	 * }
	 * */
	private Consumer<ResponseCookie.ResponseCookieBuilder> cookieCustomizer =
			(builder) -> {
//				builder.path("/").httpOnly(false);
	};
	public void setCookieCustomizer(Consumer<ResponseCookie.ResponseCookieBuilder> cookieCustomizer) {
		Assert.notNull(cookieCustomizer, "cookieCustomizer must not be null");
		this.cookieCustomizer = cookieCustomizer;
	};
	
	/**
	 * Spring Security에서 .csrfTokenRepository(....)
	 * 이렇게 설정하는데 보통 CookieCsrfTokenRepository.withHttpOnlyFalse() 이렇게 설정함.
	 * 아래를 활성화 하면 new CsrfCustomRepository.withHttpOnlyFalse()를 할 수 있는데
	 * 어차피 cookieHttpOnly를 단순히 false로만 바꾸는거라서
	 * 기본값을 false로 바꾸거나
	 * public CsrfCustomRepository() 여기서 cookieHTtpOnly를 false로
	 * 설정하면 되기때문에 굳이 사용하지 않음.
	 * */
//	public static CookieCsrfTokenRepository withHttpOnlyFalse() {
//		
//		CookieCsrfTokenRepository result = new CookieCsrfTokenRepository();
//		result.cookieHttpOnly = false;
//		
//		return result;
//	};
	
	/**
	 * CSRF 쿠키의 HttpOnly 속성을 설정
	 * 쿠키 속성을 보다 유연하게 설정하기 위해
	 * ResponseCookie.ResponseCookieBuilder를
	 * ( setCookieCustomizer )
	 * 도입한 Spring Security '6.1'에서 deprecated 됨.
	 * */
//	public void setCookieHttpOnly(boolean cookieHttpOnly) {
//		this.cookieHttpOnly = cookieHttpOnly;
//	};
	
	/**
	 * CSRF 쿠키의 도메인을 설정
	 * 쿠키 속성을 보다 유연하게 설정하기 위해
	 * ResponseCookie.ResponseCookieBuilder를
	 * ( setCookieCustomizer )
	 * 도입한 Spring Security '6.1'에서 deprecated 됨.
	 * */
//	public void setCookieDomain(String cookieDomain) {
//		this.cookieDomain = cookieDomain;
//	};
	
	/**
	 * CSRF 쿠키의 보안 속성을 설정
	 * 쿠키 속성을 보다 유연하게 설정하기 위해
	 * ResponseCookie.ResponseCookieBuilder를
	 * ( setCookieCustomizer )
	 * 도입한 Spring Security '6.1'에서 deprecated 됨.
	 * */
//	public void setSecure(Boolean secure) {
//		this.secure = secure;
//	};
	
	/**
	 * CSRF 쿠키의 최대 유효 기간을 설정
	 * 쿠키 속성을 보다 유연하게 설정하기 위해
	 * ResponseCookie.ResponseCookieBuilder를
	 * ( setCookieCustomizer )
	 * 도입한 Spring Security '6.1'에서 deprecated 됨.
	 * */
//	public void setCookieMaxAge(int cookieMaxAge) {
//		Assert.isTrue(cookieMaxAge != 0, "cookieMaxAge cannot be zero");
//		this.cookieMaxAge = cookieMaxAge;
//	};
	
}