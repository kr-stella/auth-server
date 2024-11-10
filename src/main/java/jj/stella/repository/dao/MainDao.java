package jj.stella.repository.dao;

import jj.stella.entity.dto.ReissueDto;
import jj.stella.entity.vo.RefreshTokenVo;

public interface MainDao {
	
	/** Refresh Token 존재여부 확인 */
	public RefreshTokenVo getRefreshToken(ReissueDto dto);
	
	/** 사용자의 권한 묶음 호출( 사용자 그룹, 권한 그룹, 권한 ) */
	public String getAuthorization(String id);
	
}