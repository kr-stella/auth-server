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
		
		/** 검증서버에 접근했을 때 검증로직을 건너뛰는 경로 */
		String path = request.getRequestURI();
		if(isSkipPath(path)) {
			chain.doFilter(request, response);
			return;
		}
		
		/**
		 * Request Header로 들어온 요청에 대해서만
		 * 단순 Token 문자열 추출
		 * ( 검증서버는 Cookie 사용하지 않음. )
		 * */
		String token = extractToken(request);
		
		/**
		 * 토큰이 없으면 그 즉시 비정상 접근으로 판단.
		 * 401 Error + 더 이상 로직을 진행하지 않음.
		 * "/validate", "/jti"를 인증서버 자체에서 직접 접근했을 때
		 * 요청 헤더에 없으므로 즉시 중단.
		 * */
		if(token == null) {
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED, NONE_TOKEN_ERROR_MESSAGE);
			return;
		}
		
		/** Authentication Token 복호화 */
		DecryptDto decryptAuthToken = decryptToken(token, true);
		decryptAuthToken.setToken(token);
		
		/** 검증요청이 들어오게 되면 실행되는 로직 */
		if(VALIDATE_URL.equals(path))
			handleValidate(request, response, decryptAuthToken);
		
		/** JTI 정보 요청이 들어오게 되면 실행되는 로직 - 로그아웃 */
		if(JTI_URL.equals(path))
			handleJti(response, decryptAuthToken.getJti());
		
	}
	
	/** 검증서버에 접근했을 때 검증로직을 건너뛰는 경로 */
	private boolean isSkipPath(String path) {
		return "/".equals(path)
			|| pathMatcher.match("/resources/**", path)
			|| pathMatcher.match("/favicon.ico", path);
	}
	
	/**
	 * Request Header에서 토큰 추출
	 * Cookie에서 추출하지 않는 이유는
	 * 각 서버에서 RestTemplate 등 Request Header로 들어오는 것만
	 * 정상접근으로 판단해서 허용하기 위함.
	 */
	private String extractToken(HttpServletRequest request) {
		
		String token = request.getHeader(JWT_HEADER);
		if(token != null && token.startsWith(JWT_KEY))
			return token.substring(JWT_KEY.length());
		
		return null;
		
	}
	
	/** 검증 요청에 대한 반환 */
	private void handleValidate(HttpServletRequest request, HttpServletResponse response, DecryptDto authToken) throws IOException {
		
		String id = authToken.getId();
		String jti = authToken.getJti();
//		System.out.println("authToken =====> " + authToken);
//		System.out.println("jti =====> " + jti);
//		System.out.println("id =====> " + id);
//		System.out.println("redisTemplate.hasKey(jti) =====> " + redisTemplate.hasKey(jti));
		/** #2-1. Redis에 유효한 JTI가 있다면 검증로직 실행 */
		if(redisTemplate.hasKey(jti)) {
			
			/** #3-1. 검증결과 토큰이 유효하다면 */
			authToken.setReissue(false);
			if(authToken.isSign() && validateToken(request, authToken))
				successResponse(response, authToken);
			/** #3-2. 검증결과 토큰이 유효하지 않다면 "유효하지 않은 토큰" 반환 */
			else unauthorizedResponse(response, INVALID_AUTH_TOKEN_MESSAGE);
			
		}
		
		/**
		 * #2-2. Redis에 유효한 JTI가 없다면
		 * - Remember Me DB에서 Refresh Token 존재여부 확인 및 검증
		 * - 없으면 토큰 만료 결과 반환
		 * - 있으면 Refresh Token 유효성 검사 후 인증토큰 재발행( 로그인 서버 )
		 *   > 재발행 후 인증토큰 유효성 검사 후 반환
		 * */
		else {
			/** 토큰 재발급 로직 - Remember Me DB에 Refresh Token 존재여부 확인 후 재발급 */
			handleReissue(request, response, id, jti.split("::")[1]);
		}
		
	}
	
	/** JTI 정보 요청에 대한 반환 */
	private void handleJti(HttpServletResponse response, String jti) throws IOException {
		
		response.setStatus(HttpServletResponse.SC_OK);
		response.setContentType(MediaType.TEXT_PLAIN_VALUE);
		response.setCharacterEncoding("UTF-8");
		response.getWriter().write(jti);
		response.getWriter().flush();
		
		return;
		
	}
	
	/**
	 * #3. Remember Me DB에 Refresh Token 존재여부 확인 후 재발급
	 * - Redis에 유효한 JTI가 없다면 토큰 재발급 로직 실행
	 * */
	private void handleReissue(HttpServletRequest request, HttpServletResponse response, String id, String device) throws IOException {
		
		/** Remember Me DB에서 Refresh Token 존재여부 확인을 위한 데이터 설정 */
		ReissueDto dto = new ReissueDto();
		dto.setId(id);
		dto.setDevice(device);
		
		/** Refresh Token 존재여부 확인 */
		RefreshTokenVo refreshToken = mainDao.getRefreshToken(dto);
		
		/** #3-1. Refresh Token이 존재한다면 검증 + 재발급 요청 */
		if(refreshToken != null) {
			
			DecryptDto decryptRefreshToken = decryptToken(refreshToken.getToken(), false);
			decryptRefreshToken.setToken(refreshToken.getToken());
			/** #3-1-1. Refresh Token의 검증결과가 유효하다면 재발행 요청 */
			if(decryptRefreshToken.isSign() && validateToken(request, decryptRefreshToken))
				reissueRequestAndValidateToken(request, response, decryptRefreshToken);
			
			/** #3-1-2. Refresh Token의 검증결과가 유효하지 않다면 "유효하지 않은 토큰" 반환 */
			else unauthorizedResponse(response, INVALID_REFRESH_TOKEN_MESSAGE);
			
		}
		
		/** #3-2. Refresh Token이 존재하지 않는다면 "토큰 만료" 반환 */
		else unauthorizedResponse(response, EXPIRED_TOKEN_MESSAGE);
		
	}
	
	/** 재발행 요청, 새로 발급받은 토큰의 검증 */
	private void reissueRequestAndValidateToken(HttpServletRequest request, HttpServletResponse response, DecryptDto dto) throws IOException {
		
		RestTemplate template = new RestTemplate();
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_JSON);
		headers.set("REISSUE-ID", dto.getId());
		headers.set("REISSUE-IP", dto.getIp());
		headers.set("REISSUE-AGENT", dto.getAgent());
		headers.set("REISSUE-DEVICE", dto.getDevice());
		HttpEntity<String> entity = new HttpEntity<>("", headers);
		try {
			
			/** #4. 재발행 요청 */
			ResponseEntity<String> res = template.exchange(
				REFRESH_SERVER, HttpMethod.GET, entity, String.class
			);
			
			String reissueAuthToken = res.getBody();
			/** #4-1. 새로 발급받은 토큰이 정상적이라면 */
			if(!reissueAuthToken.equals("INVALID")) {
				
				DecryptDto decryptReissueAuthToken = decryptToken(reissueAuthToken, true);
				decryptReissueAuthToken.setReissue(true);
				decryptReissueAuthToken.setToken(reissueAuthToken);
				if(validateToken(request, decryptReissueAuthToken))
					successResponse(response, decryptReissueAuthToken);
				else unauthorizedResponse(response, INVALID_AUTH_TOKEN_MESSAGE);
				
			}

			/** #4-2. 새로 발급받은 토큰이 비정상적이라면 */
			else unauthorizedResponse(response, INVALID_AUTH_TOKEN_MESSAGE);
			
		} catch(HttpClientErrorException e) {
			e.printStackTrace();
			unauthorizedResponse(response, INVALID_AUTH_TOKEN_MESSAGE);
		} catch(RestClientException e) {
			e.printStackTrace();
			unauthorizedResponse(response, INVALID_AUTH_TOKEN_MESSAGE);
		}
		
		return;
		
	}
	
	/** 토큰 복호화 후 필요한 값들을 담아서 return */
	private DecryptDto decryptToken(String token, boolean isAuth) {
		
		DecryptDto res = new DecryptDto();
		try {
			
			/** JWE 복호화 */
			JWEObject jweObject = JWEObject.parse(token);
			
			DirectDecrypter decrypter = new DirectDecrypter((isAuth? JWT_DECRYPT_TOKEN:JWT_DECRYPT_REFRESH_TOKEN).getEncoded());
			jweObject.decrypt(decrypter);
			
			/** 복호화 된 JWE에서 토큰 추출 및 파싱 */
			SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();
			
			/** 서명 검증 */
			JWSVerifier verifier = new MACVerifier((isAuth? JWT_DECRYPT_SIGN:JWT_DECRYPT_REFRESH_SIGN).getEncoded());
			/** 서명 검증결과 >>> true = 검증O / false = 검증X */
			res.setSign(signedJWT.verify(verifier));
			
			/** JWT Claims */
			JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
			
			/** 토큰에서 만료일 추출 */
			res.setExpired(claims.getExpirationTime());
			/** 토큰에서 사용자 ID 추출 */
			res.setId(claims.getSubject());
			/** 토큰에서 로그인을 시도했던 사용자의 IP 추출 */
			res.setIp(claims.getClaim("ip").toString());
			/** 토큰에서 로그인을 시도했던 사용자의 Agent 추출 */
			res.setAgent(claims.getClaim("agent").toString());
			/** 토큰에서 사용자의 기기 식별번호 추출 ( id::uuid 형식 ) */
			String jti = claims.getJWTID(); 
			res.setJti(jti);
			res.setDevice(jti.split("::")[1]);
			
		} catch(ParseException | JOSEException e) {
			e.printStackTrace();
			res = new DecryptDto();
		}
		
		return res;
		
	}
	
	/** 토큰 검증 로직 */
	private boolean validateToken(HttpServletRequest request, DecryptDto dto) {
		
		Date expired = dto.getExpired();
		String agent = dto.getAgent();
		/**
		 * ### 유효한 경우 = 아래 조건을 통과해야 함. ###
		 * #1. 만료일이 현재시간보다 이후인 경우
		 * #2. Agent가 같은 경우
		 * #3. 현재 User-Agent가 모바일인 경우에는 Device 혹은 Ip가 일치해야 함. 
		 * - 만약 User-Agent가 모바일이 아닌경우에는 Device와 Ip가 일치해야 함.
		 */
		String reqAgent = request.getHeader("User-Agent");

//		System.out.println("갑자기 한번씩 풀리는 오류확인을 위한 로그");
//		System.out.println("검증요청이 들어온 Token ===> " + dto.getToken());
//		System.out.println("expired ====> " + expired);
//		System.out.println("new Date ====> " + new Date());
		/** 시간차 오차범위 Redis와 Server */
		long diff = (new Date().getTime() - expired.getTime()) / 1000;
		if(expired.before(new Date())) {
			
//			System.out.println("만료됐는디..?");
//			System.out.println("만려됐는데 오차범위 내로 true return 함");
			if(diff <= 30)
				return true;
			
			return false;
			
		}
		
//		System.out.println("여기도오니..?? agent검증... ===> " + reqAgent.equals(agent));
		return reqAgent.equals(agent);
		
	}
	
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
		 * */
		map.put("authz", mainDao.getAuthorization(dto.getId()));
		
		ObjectMapper mapper = new ObjectMapper();
		String result = mapper.writeValueAsString(map);
		
		response.getWriter().write(result);
		response.getWriter().flush();
		
		return;
		
	}
	
	private void unauthorizedResponse(HttpServletResponse response, String str) throws IOException {
		
		/** 유효하지 않은 토큰 결과 반환 */
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		response.setContentType(MediaType.TEXT_PLAIN_VALUE);
		response.setCharacterEncoding("UTF-8");
		response.getWriter().write(str);
		response.getWriter().flush();
		
		return;
		
	}
	
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
//	}
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
//	}
//	
//	/**
//	 * IP 주소가 유효한지 검증.
//	 * @param ip 검증할 IP 주소
//	 * @return 유효성 검사 결과
//	 */
//	private boolean isValid(String ip) {
//		return ip != null && !ip.isEmpty() && !"unknown".equalsIgnoreCase(ip);
//	}
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
//	}
	
}