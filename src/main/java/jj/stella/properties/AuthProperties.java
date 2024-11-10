package jj.stella.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Configuration
// auth.* 매핑
@ConfigurationProperties(prefix = "auth")
public class AuthProperties {
	
	// auth.jwt.* 매핑
	private Jwt jwt;
	
	@Getter
	@Setter
	public static class Jwt {
		
		private String header;		// auth.jwt.header
		private String key;			// auth.jwt.key
		
		// auth.jwt.decrypt.* 매핑
		private Decrypt decrypt;
		
		@Getter
		@Setter
		public static class Decrypt {
			
			private String sign;	// auth.jwt.decrypt.sign
			private String token;	// auth.jwt.decrypt.token
			
			// auth.jwt.decrypt.refresh.* 매핑
			private Refresh refresh;
			
			@Getter
			@Setter
			public static class Refresh {
				
				private String sign;	// auth.jwt.decrypt.refresh.sign
				private String token;	// auth.jwt.decrypt.refresh.token
				
			};
			
		};
		
	};
	
	// auth.csrf.* 매핑
	private Csrf csrf;
	
	@Getter
	@Setter
	public static class Csrf {
		
		private String name;		// auth.csrf.name
		private String parameter;	// auth.csrf.parameter
		private String header;		// auth.csrf.header
		
	};
	
}