package jj.stella.filter.auth;

import java.io.IOException;
import java.security.Key;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jj.stella.entity.dto.DecryptDto;
import jj.stella.entity.dto.ReissueDto;
import jj.stella.entity.vo.RefreshTokenVo;
import jj.stella.repository.dao.MainDao;

public class JwtAuthentication extends OncePerRequestFilter {
	
	private static final String VALIDATE_URL = "/validate";
	private static final String JTI_URL = "/jti";
	
	private static final String NONE_TOKEN_ERROR_MESSAGE = "잘못된 요청입니다.";
	private static final String EXPIRED_TOKEN_MESSAGE = "Authentication Token is expired.";
	private static final String INVALID_AUTH_TOKEN_MESSAGE = "Authentication Token is invalid.";
	private static final String INVALID_REFRESH_TOKEN_MESSAGE = "Refresh Token is invalid.";
	
	private String JWT_HEADER;
	private String JWT_KEY;
	private Key JWT_DECRYPT_SIGN;
	private Key JWT_DECRYPT_TOKEN;
	private Key JWT_DECRYPT_REFRESH_SIGN;
	private Key JWT_DECRYPT_REFRESH_TOKEN;
	private String REFRESH_SERVER;
	
	private MainDao mainDao;
	private RedisTemplate<String, String> redisTemplate;
	private final AntPathMatcher pathMatcher = new AntPathMatcher();
	public JwtAuthentication(
		String JWT_HEADER, String JWT_KEY,
		Key JWT_DECRYPT_SIGN, Key JWT_DECRYPT_TOKEN,
		Key JWT_DECRYPT_REFRESH_SIGN, Key JWT_DECRYPT_REFRESH_TOKEN,
		String REFRESH_SERVER, MainDao mainDao, RedisTemplate<String, String> redisTemplate
	) {
		this.JWT_HEADER = JWT_HEADER;
		this.JWT_KEY = JWT_KEY;
		this.JWT_DECRYPT_SIGN = JWT_DECRYPT_SIGN;
		this.JWT_DECRYPT_TOKEN = JWT_DECRYPT_TOKEN;
		this.JWT_DECRYPT_REFRESH_SIGN = JWT_DECRYPT_REFRESH_SIGN;
		this.JWT_DECRYPT_REFRESH_TOKEN = JWT_DECRYPT_REFRESH_TOKEN;
		this.REFRESH_SERVER = REFRESH_SERVER;
		this.mainDao = mainDao;
		this.redisTemplate = redisTemplate;
	}
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
		throws ServletException, IOException {
		
		/** 1. 검증서버에 접근했을 때 검증로직을 건너뛰는 경로 */
		String path = request.getRequestURI();
		if(isSkipPath(path)) {
			chain.doFilter(request, response);
			return;
		};
		
		/**
		 * 2. 검증로직을 건너뛰는 경로가 아닌 경우 토큰을 추출함
		 * - 토큰을 추출해서 값이 있다면 해당 토큰으로 검증로직을 결과를 반환
		 * - 검증서버에서는 Cookie에 저장된 토큰을 사용하지 않고,
		 *   다른 MSA 서버에서 내가 정한 규칙대로 요청한 경우 토큰을 추출해서 활용함
		 *   요청 헤더 key : Authorization
		 *   요청 값 : Bearer ..... Token .....
		 * */
		String token = extractToken(request);
		
		/**
		 * 3. 토큰이 없다면 그 즉시 비정상 접근으로 판단
		 * 401에러 반환 + 더 이상 로직을 진행하지 않음
		 * - 검증서버에서 "/validate", "/jti"에 직접 접근해도
		 *   요청 헤더가 없기 때문에 즉시 중단
		 * */
		if(token == null) {
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, NONE_TOKEN_ERROR_MESSAGE);
			return;
		};
		
		/**
		 * 4. 토큰이 있다면 복호화 진행
		 * - 일반 JWT Token이 아니라 JWT Token을 암호화 한 JWE로 관리하기 때문에
		 *  > decryptToken( 추출한 재발급 토큰, 인증 토큰유무 _ 인증 토큰인지, 재발급 토큰인지 구분자: true: 인증 토큰 / false: 재발급 토큰 )
		 * */
		DecryptDto decryptAuthToken = decryptToken(token, true);
		decryptAuthToken.setToken(token);
		
		/** 5-1. 토큰이 있고, 검증 요청경로( /validate )인 경우 검증 후 결과 반환 */
		if(VALIDATE_URL.equals(path))
			handleValidate(request, response, decryptAuthToken);
		
		/**
		 * 5-2. JTI 요청경로( /jti )인 경우는
		 * 다른 MSA 서버에 비정상 접근이 감지됐거나, 로그아웃 요청이 들어온 경우
		 * - 이 정보를 토대로 DB에 저장된 remember me를 지우거나, Redis에 저장된 인증정보를 지움
		 * */
		if(JTI_URL.equals(path))
			handleJti(response, decryptAuthToken.getJti());
		
	};
	
	/** 검증서버에 접근했을 때 검증로직을 건너뛰는 경로 */
	private boolean isSkipPath(String path) {
		return "/".equals(path)
			|| pathMatcher.match("/resources/**", path)
			|| pathMatcher.match("/favicon.ico", path);
	};
	
	/**
	 * 요청 헤더에서 토큰 추출
	 * - 검증서버에서는 Cookie에 저장된 토큰을 사용하지 않고,
	 *   다른 MSA 서버에서 RestTemplate 등 요청 헤더에 설정한 값( 내가 정한 규칙 )으로
	 *   토큰을 추출해서 활용함
	 * */
	private String extractToken(HttpServletRequest request) {
		
		/** 요청 헤더에 Authorization이( JWT_HEADER ) 있는지 확인 */
		String token = request.getHeader(JWT_HEADER);
		/**
		 * 요청 헤더에 Authorization가 있고( 토큰이 있고 )
		 * Bearer( JWT_KEY )로 시작하는 경우
		 * */
		if(token != null && token.startsWith(JWT_KEY))
			return token.substring(JWT_KEY.length());
		
		/** 위 경우가 아니라면 비정상 접근으로 판단하고 null 반환 */
		return null;
		
	};
	
	/** 토큰 복호화 후 필요한 정보 반환 */
	private DecryptDto decryptToken(String token, boolean isAuth) {
		
		DecryptDto decrypt = new DecryptDto();
		try {
			
			DirectDecrypter decrypter = new DirectDecrypter((isAuth? JWT_DECRYPT_TOKEN:JWT_DECRYPT_REFRESH_TOKEN).getEncoded());
			
			/** JWE 복호화 */
			JWEObject jweObject = JWEObject.parse(token);
			jweObject.decrypt(decrypter);
			
			/** 복호화 된 JWE에서 토큰 추출 및 파싱 */
			SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();
			
			/** 서명 검증 */
			JWSVerifier verifier = new MACVerifier((isAuth? JWT_DECRYPT_SIGN:JWT_DECRYPT_REFRESH_SIGN).getEncoded());
			/** 서명 검증결과 >>> true = 검증O / false = 검증X */
			decrypt.setSign(signedJWT.verify(verifier));
			
			/** JWT Claims */
			JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
			/** 토큰에서 만료일 추출 */
			decrypt.setExpired(claims.getExpirationTime());
			/** 토큰에서 사용자 ID 추출 */
			decrypt.setId(claims.getSubject());
			/** 토큰에서 첫 로그인을 시도했던 사용자의 IP 추출 */
			decrypt.setIp(claims.getClaim("ip").toString());
			/** 토큰에서 첫 로그인을 시도했던 사용자의 Agent 추출 */
			decrypt.setAgent(claims.getClaim("agent").toString());
			/** 토큰에서 사용자의 기기 식별번호 추출 ( id::uuid 형식 ) */
			String jti = claims.getJWTID();
			decrypt.setJti(jti);
			decrypt.setDevice(jti.split("::")[1]);
			
		} catch(ParseException | JOSEException e) {
			e.printStackTrace();
			decrypt = new DecryptDto();
		}
		
		return decrypt;
		
	};
	
	/** 검증 요청에 대한 반환 */
	private void handleValidate(HttpServletRequest request, HttpServletResponse response, DecryptDto authToken) throws IOException {
		
		String id = authToken.getId();
		String jti = authToken.getJti();
//		System.out.println("authToken =====> " + authToken);
//		System.out.println("jti =====> " + jti);
//		System.out.println("id =====> " + id);
//		System.out.println("redisTemplate.hasKey(jti) =====> " + redisTemplate.hasKey(jti));
		
		/** 5-1-1. Redis에 유효한 JTI가 있다면( = 정상적으로 로그인 한 사용자라면 ) 검증로직 실행 */
		if(redisTemplate.hasKey(jti)) {
			
			/** 반환되는 서버에 재발급된 토큰이 아니라고 알려줌 */ 
			authToken.setReissue(false);
			
			/**
			 * 5-1-1-1. 토큰의 서명이 참이고, 검증결과 토큰이 유효하다면 성공 반환
			 * - 검증을 요청한 서버( 반환받는 서버 )에서 Cookie 만료시간과 Redis 만료시간을 갱신함
			 * */
			if(authToken.isSign() && validateToken(request, authToken))
				successResponse(response, authToken);
			
			/**
			 * 5-1-1-2. 위 경우가 아니라면 "유효하지 않은 토큰" 반환
			 * - 유효하지 않음 반환 > 검증을 요청한 서버( 반환받는 서버 )에서 해당 결과를 받음 > 사용자에게 보여줌 > 로그아웃
			 * */
			else unauthorizedResponse(response, INVALID_AUTH_TOKEN_MESSAGE);
			
		}
		
		/**
		 * 5-1-2. Redis에 유효한 JTI가 없다면( = 로그인 허용 시간이 만료됐다면 )
		 * - 로그인 할 때 Remember Me를 선택했는지 확인 ( Remember Me DB 확인 )
		 *  > remember me 테이블에 재발급 토큰 존재여부 확인 및 검증
		 *  > 있다면( 자동로그인 유저라면 ) 재발급 토큰 유효성 검사 후 인증토큰 재발행 ( 로그인 서버에서 발급함 )
		 *  > 없다면( 일반 로그인 유저라면 ) 토큰 만료 결과 반환
		 * */
		else handleReissue(request, response, id, jti.split("::")[1]);
		
	};
	
	/**
	 * JTI 정보 요청에 대한 반환
	 * - 다른 MSA 서버에 비정상 접근이 감지됐거나, 로그아웃 요청이 들어온 경우
	 *  > 이 정보를 토대로 DB에 저장된 remember me를 지우거나, Redis에 저장된 인증정보를 지움
	 * */
	private void handleJti(HttpServletResponse response, String jti) throws IOException {
		
		response.setStatus(HttpServletResponse.SC_OK);
		response.setContentType(MediaType.TEXT_PLAIN_VALUE);
		response.setCharacterEncoding("UTF-8");
		response.getWriter().write(jti);
		response.getWriter().flush();
		
		return;
		
	};
	
	/** 토큰 검증 로직 */
	private boolean validateToken(HttpServletRequest request, DecryptDto dto) {
		
		Date expired = dto.getExpired();
		String agent = dto.getAgent();
		
		/**
		 * 유효하다의 조건( 아래 조건을 모두 만족해야 함 )
		 * (1) 만료일이 현재시간보다 이후인 경우
		 * (2) User-Agent가 특정 조건에 맞아야 함 ( 상세 조건 구현x )
		 *  > User-Agent가 모바일인 경우에는 Device 혹은 Ip가 일치해야 함.
		 *  > User-Agent가 모바일이 아닌경우에는 Device와 Ip가 일치해야 함.
		 */
		String reqAgent = request.getHeader("User-Agent");
		
		/** 시간차 오차범위 Redis와 Server */
		long diff = (new Date().getTime() - expired.getTime()) / 1000;
		if(expired.before(new Date())) {
			
			if(diff <= 30)
				return true;
			
			return false;
			
		};
		
		return reqAgent.equals(agent);
		
	};
	
	/**
	 * 5-1-2. 로그인 할 때 Remember Me를 선택했는지 확인 ( Remember Me DB 확인 )
	 *  > remember me 테이블에 재발급 토큰 존재여부 확인 및 검증
	 *  > 있다면( 자동로그인 유저라면 ) 재발급 토큰 유효성 검사 후 인증토큰 재발행 ( 로그인 서버에서 발급함 )
	 *  > 없다면( 일반 로그인 유저라면 ) 토큰 만료 결과 반환
	 * */
	private void handleReissue(HttpServletRequest request, HttpServletResponse response, String id, String device) throws IOException {
		
		/** Remember Me DB에서 재발급 토큰 존재여부 확인을 위한 데이터 설정 */
		ReissueDto dto = new ReissueDto();
		dto.setId(id);
		dto.setDevice(device);
		
		/** 재발급 토큰 존재여부 확인 */
		RefreshTokenVo refreshToken = mainDao.getRefreshToken(dto);
		
		/** 5-1-2-1. 재발급 토큰이 존재한다면 유효성 검사 + 재발급 요청 */
		if(refreshToken != null) {
			
			/**
			 * 5-1-2-1-1. 토큰이 있다면 복호화 진행
			 * - 일반 재발급 토큰( JWT )이 아니라 재발급 토큰( JWT )을 암호화 한 JWE로 관리하기 때문에
			 *  > decryptToken( 추출한 재발급 토큰, 인증 토큰유무 _ 인증 토큰인지, 재발급 토큰인지 구분자: true: 인증 토큰 / false: 재발급 토큰 )
			 * */
			DecryptDto decryptRefreshToken = decryptToken(refreshToken.getToken(), false);
			decryptRefreshToken.setToken(refreshToken.getToken());
			
			/** 5-1-2-1-2. 재발급 토큰의 서명이 참이고, 검증결과 재발급 토큰이 유효하다면 재발급 요청 & 재발급된 토큰 검증 */
			if(decryptRefreshToken.isSign() && validateToken(request, decryptRefreshToken))
				reissueRequestAndValidateToken(request, response, decryptRefreshToken);
			
			/** 5-1-2-1-3. 재발급 토큰의 유효성 검사 결과가 유효하지 않다면 "유효하지 않은 토큰" 반환 */
			else unauthorizedResponse(response, INVALID_REFRESH_TOKEN_MESSAGE);
			
		}
		
		/** 5-1-2-2. Refresh Token이 존재하지 않는다면 "토큰 만료" 반환 */
		else unauthorizedResponse(response, EXPIRED_TOKEN_MESSAGE);
		
	};
	
	/** 5-1-2-1-2. 재발급 토큰의 서명이 참이고, 검증결과 재발급 토큰이 유효하다면 재발급 요청 & 재발급된 토큰 검증 */
	private void reissueRequestAndValidateToken(HttpServletRequest request, HttpServletResponse response, DecryptDto dto) throws IOException {
		
		RestTemplate template = new RestTemplate();
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_JSON);
		
		/**
		 * 내가 정한 규칙대로 로그인 서버에 토큰 재발급 요청
		 * - 아래 요청 헤더로 인증토큰 재발급 함
		 * */
		headers.set("REISSUE-ID", dto.getId());
		headers.set("REISSUE-IP", dto.getIp());
		headers.set("REISSUE-AGENT", dto.getAgent());
		headers.set("REISSUE-DEVICE", dto.getDevice());
		HttpEntity<String> entity = new HttpEntity<>("", headers);
		try {

			/** 인증 토큰 재발급 요청 */
			ResponseEntity<String> res = template.exchange(REFRESH_SERVER, HttpMethod.GET, entity, String.class);
			String reissueAuthToken = res.getBody();
			/** 새로 발급받은 토큰이 정상적이라면 */
			if(!reissueAuthToken.equals("INVALID")) {
				
				/**
				 * 5-1-2-1-2-1. 새로 발급받은 토큰 복호화 진행
				 * - 암호화 한 JWE로 관리하기 때문에
				 *  > decryptToken( 추출한 재발급 토큰, 인증 토큰유무 _ 인증 토큰인지, 재발급 토큰인지 구분자: true: 인증 토큰 / false: 재발급 토큰 )
				 * */
				DecryptDto decryptReissueAuthToken = decryptToken(reissueAuthToken, true);
				/** 반환되는 서버에 재발급된 토큰이라고 알려줌 */ 
				decryptReissueAuthToken.setReissue(true);
				decryptReissueAuthToken.setToken(reissueAuthToken);
				
				/** 5-1-2-1-2-2. 재발급 된 토큰이 유효하다면 성공 반환 */
				if(validateToken(request, decryptReissueAuthToken))
					successResponse(response, decryptReissueAuthToken);
				/** 5-1-2-1-2-3. 아닌 경우 오류 반환 */
				else unauthorizedResponse(response, INVALID_AUTH_TOKEN_MESSAGE);
				
			}

			/** #4-2. 새로 발급받은 토큰이 비정상적이라면 오류 반환 */
			else unauthorizedResponse(response, INVALID_AUTH_TOKEN_MESSAGE);
			
		} catch(HttpClientErrorException e) {
			e.printStackTrace();
			unauthorizedResponse(response, INVALID_AUTH_TOKEN_MESSAGE);
		} catch(RestClientException e) {
			e.printStackTrace();
			unauthorizedResponse(response, INVALID_AUTH_TOKEN_MESSAGE);
		}
		
		return;
		
	};
	
	/**
	 * 성공 반환
	 * */
	private void successResponse(HttpServletResponse response, DecryptDto dto) throws IOException {
		
		response.setStatus(HttpServletResponse.SC_OK);
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding("UTF-8");
		
		Map<String, Object> map = new HashMap<>();
		map.put("reissue", dto.isReissue());
		map.put("id", dto.getId());
		map.put("jti", dto.getJti());
		map.put("token", dto.getToken());
		
		/**
		 * 사용자의 권한에 Redis 적용해둠.
		 * 만약 권한에 변경이 있다면 "@CacheEvict" 혹은 RedisTemplate 혹은 커스텀 AOP를 활용해서
		 * 사용자::authz를 제거해야 함.
		 * 
		 * authz 정보는 아래와 같음
		 * (1) userGroup<String>: 사용자 그룹
		 * (2) roleGroups<List>: 권한 그룹 리스트
		 * (3) roles<List>: 권한 리스트
		 * */
		map.put("authz", mainDao.getAuthorization(dto.getId()));
		
		ObjectMapper mapper = new ObjectMapper();
		String result = mapper.writeValueAsString(map);
		
		response.getWriter().write(result);
		response.getWriter().flush();
		
		return;
		
	};
	
	/**
	 * 오류 반환
	 */
	private void unauthorizedResponse(HttpServletResponse response, String str) throws IOException {
		
		/** 유효하지 않은 토큰 결과 반환 */
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		response.setContentType(MediaType.TEXT_PLAIN_VALUE);
		response.setCharacterEncoding("UTF-8");
		response.getWriter().write(str);
		response.getWriter().flush();
		
		return;
		
	};
	
	
	
	
	
//	private boolean isMobileAgent(String agent) {
//		
//		/** 모바일 기기 및 SNS 앱 내 브라우저의 User-Agent에 일반적으로 포함되는 키워드 목록 */
//		String[] keywords = {
//				
//			"Mobile", "Android", "iPhone", "iPad", "iPod", "Opera Mini", 
//			"IEMobile", "WPDesktop", "Fennec", "BlackBerry", "BB10", 
//			"webOS", "Kindle", "Silk", "Vodafone", "UCBrowser", "Samsung", 
//			"Sony", "Symbian", "Nokia", "Windows Phone", "HTC", "MQQBrowser",
//			
//			// SNS 앱 내 브라우저 및 특정 앱에 의해 설정되는 User-Agent 부분 문자열
//			"FBAN", "FBAV", "Twitter", "Instagram", "Line", "KAKAOTALK",
//			"Snapchat", "Pinterest", "Reddit", "Tumblr", "Telegram", 
//			"WeChat", "QQBrowser", "Daum", "Naver", "Yahoo", "Bing"
//			
//		};
//		
//		/**
//		 * User-Agent 문자열이 null이거나 비어있는 경우,
//		 * 모바일 기기가 아닌 것으로 간주
//		 */
//		if(agent == null || agent.isEmpty())
//			return false;
//
//		/** User-Agent 문자열을 대소문자 구분 없이 검사 */
//		String lowerAgent = agent.toLowerCase();
//		for(String keyword:keywords) {
//			/** User-Agent에 해당 키워드가 포함되어 있으면 모바일 기기 또는 SNS 앱 내 브라우저로 판단 */
//			if(lowerAgent.contains(keyword.toLowerCase()))
//				return true;
//		}
//		
//		/** 모든 키워드가 포함되어 있지 않으면 모바일 기기 또는 SNS 앱 내 브라우저가 아님 */
//		return false;
//		
//	};
//	
//	/** 클라이언트 실제 IP 주소를 찾기 위한 헤더 목록 */
//	private static final List<String> HEADERS = Arrays.asList(
//		"X-Forwarded-For", "Proxy-Client-IP", "WL-Proxy-Client-IP", "HTTP_X_FORWARDED_FOR",
//		"HTTP_X_FORWARDED", "HTTP_FORWARDED_FOR", "HTTP_FORWARDED", "HTTP_CLIENT_IP", "HTTP_VIA"
//	);
//	
//	private Optional<String> findIp(HttpServletRequest request, String api) {
//		return HEADERS.stream()
//				/**
//				 * 각 헤더에 대한 요청 값을 매핑
//				 * request::getHeader === request.getHeader(name)
//				 * 여기서 name은 stream의 각 요소
//				 */
//				.map(request::getHeader)
//				/** 유효한 IP 주소만 필터링 */
//				.filter(this::isValid)
//				/** 첫 번째 유효한 IP 주소 찾기 */
//				.findFirst()
//				/** IP 주소가 여러 개일 경우 첫 번째만 사용 */
//				.map(ip -> ip.split(",")[0].trim())
//				/**
//				 * 외부 서비스를 통해 IP를 가져오는 백업 방식
//				 * 위 절차의 최종값이 Null이라면 외부 서비스로 Ip를 호출 후 검증.
//				 */
//				.or(() -> Optional.ofNullable(fetchIp(api)).filter(this::isValid));
//	};
//	
//	/**
//	 * IP 주소가 유효한지 검증.
//	 * @param ip 검증할 IP 주소
//	 * @return 유효성 검사 결과
//	 */
//	private boolean isValid(String ip) {
//		return ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip);
//	};
//	
//	/**
//	 * 외부 서비스를 통해 공인 IP 주소를 호출.
//	 * @return 공인 IP 주소 또는 에러 메시지
//	 */
//	private static final int TIMEOUT = 2000;
//	private String fetchIp(String api) {
//		
//		try {
//			
//			HttpURLConnection connection = (HttpURLConnection) new URL(api).openConnection();
//			connection.setRequestMethod("GET");
//			// n초 내에 연결되어야 함
//			connection.setConnectTimeout(TIMEOUT);
//			// n초 내에 데이터를 읽어야 함
//			connection.setReadTimeout(TIMEOUT);
//			
//			int resCode = connection.getResponseCode();
//			if(resCode == HttpURLConnection.HTTP_OK) {
//				try(BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
//					return reader.readLine();
//				}
//			} else
//				System.out.println("공인 IP주소 호출 GET요청 실패 / Response Code: " + resCode);
//			
//		} catch(IOException e) {
//			System.err.println("Error fetching IP: " + e.getMessage());
//		}
//		
//		return null;
//		
//	};
	
}