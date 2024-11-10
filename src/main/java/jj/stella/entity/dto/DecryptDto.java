package jj.stella.entity.dto;

import java.util.Date;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class DecryptDto {
	
	/** 복호화 타입 - Reissue Token인지 */
	private boolean reissue;
	
	/** 전체 토큰 */
	private String token;
	
	/** 서명 검증 여부 */
	private boolean sign;
	
	/** Claims List */
	private Date expired;
	private String id;
	private String ip;
	private String jti;
	private String agent;
	private String device;
	
}