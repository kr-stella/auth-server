package jj.stella.filter.csrf;

import java.io.Serializable;
import java.util.function.Supplier;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;
import org.springframework.util.Assert;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class CsrfHandler implements CsrfTokenRequestHandler {

	private String CSRF_PARAMETER;
	/**
	 * 요청 속성으로 사용할 추가 CsrfToken 이름을 설정
	 * 기본적으로 CsrfToken#getParameterName()과 동일한 추가 요청 속성이 설정됩니다.
	 * 왜? 내가 이 위에 바로 "_csrf"를 설정했기 때문
	 * 이 메소드를 사용해서 재정의가 가능함.
	 * 즉 다른데서 (CsrfToken) req.getAttribute("_csrf");를 해도
	 * CsrfToken을 얻을 수 있음.
	 * handle에서 request.setAttribute(csrfAttrName, csrfToken);를
	 * 해주고있기 때문
	 * 
	 * SecurityConfig에서 적용하려면 이렇게 작성해야 함.
	 * 
	 * ...
	 * .csrf(csrf -> csrf.csrfTokenRepository(csrfTokenRepository))
	 * ...
	 * 
	 * Bean 등록
	 * private CsrfCustomHandler csrfCustomHandler() {
	 * 
	 * 		CsrfCustomHandler handler = new CsrfCustomHandler();
	 * 		handler.setCsrfParameter("newAttrName");
	 * 
	 * 		return repo;
	 * 
	 * }
	 */
	public CsrfHandler(String CSRF_PARAMETER) {
		this.CSRF_PARAMETER = CSRF_PARAMETER;
	};
	
	public final void setCsrfParameter(String CSRF_PARAMETER) {
		this.CSRF_PARAMETER = CSRF_PARAMETER;
	};
	
	public void handle(HttpServletRequest request, HttpServletResponse response,
		Supplier<CsrfToken> deferredToken) {
		
		Assert.notNull(request, "request cannot be null");
		Assert.notNull(response, "response cannot be null");
		Assert.notNull(deferredToken, "deferredCsrfToken cannot be null");
		
		/** 요청 객체에 응답 객체를 속성으로 추가 ( 아직 다른데서 쓰임새x ) */
		request.setAttribute(HttpServletResponse.class.getName(), response);
		/** 지연 로딩을 사용하여 CsrfToken 객체 생성 */
		CsrfToken csrfToken = new SupplierCsrfToken(deferredToken);
		/**
		 * 요청 객체에 CsrfToken 객체를 속성으로 추가
		 * 다른데서 아래처럼 호출하기 위함.
		 * CsrfToken csrf = (CsrfToken) req.getAttribute(CsrfToken.class.getName());
		 * csrf.getHeaderName(), csrf.getParameterName(), csrf.getToken()
		 * */
		request.setAttribute(CsrfToken.class.getName(), csrfToken);
		/**
		 * 사용자 정의 속성 이름이 설정되었다면 해당 이름으로도 CsrfToken 객체를 속성으로 추가
		 * */
		String newAttrName = (this.CSRF_PARAMETER != null)?
			this.CSRF_PARAMETER:csrfToken.getParameterName();
		/**
		 * 만약 XSRF-TOKEN이 아니라 다른걸로 호출하려면
		 * csrfRequestAttributeName를 변경해야 함.
		 * 그래서 다른데에서 아래처럼 호출
		 * (CsrfToken) req.getAttribute("ABCDEFG");
		 */
		request.setAttribute(newAttrName, csrfToken);
		
	};
	/**
	 * Supplier 인터페이스를 사용하여
	 * CsrfToken 객체를 지연 로딩 방식으로 제공하는 내부 클래스.
	 */
	private static final class SupplierCsrfToken implements CsrfToken, Serializable {
		
		private static final long serialVersionUID = 1L;
		
		private final Supplier<CsrfToken> supplier;
		private SupplierCsrfToken(Supplier<CsrfToken> supplier) {
			this.supplier = supplier;
		};
		
		@Override
		public String getHeaderName() {
			return getCsrf().getHeaderName();
		};
		@Override
		public String getParameterName() {
			return getCsrf().getParameterName();
		};
		@Override
		public String getToken() {
			return getCsrf().getToken();
		};
		
		private CsrfToken getCsrf() {
			
			CsrfToken token = this.supplier.get();
			if(token == null)
				throw new IllegalStateException("supplier returned null getCsrf");
			
			return token;
			
		};
		
	};
	
};