package jj.stella.repository.dao;

import org.apache.ibatis.session.SqlSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;

import com.nimbusds.jose.shaded.gson.Gson;

import jakarta.annotation.Resource;
import jj.stella.entity.dto.ReissueDto;
import jj.stella.entity.vo.AuthorizationVo;
import jj.stella.entity.vo.RefreshTokenVo;

@Repository
public class MainDaoImpl implements MainDao {
	
	@Resource(name="sqlSessionTemplate")
	private SqlSession sqlSession;
	
	@Autowired
	private RedisTemplate<String, Object> redisTemplate;
	
	public void setSqlSession(SqlSession sqlSession) {
		this.sqlSession = sqlSession;
	}
	
	/** Refresh Token 존재여부 확인 */
	@Override
	public RefreshTokenVo getRefreshToken(ReissueDto dto) {
		return sqlSession.selectOne("getRefreshToken", dto);
	};
	
	/** 사용자의 권한 묶음 호출( 사용자 그룹, 권한 그룹, 권한 ) */
	@Override
	public String getAuthorization(String id) {
		
		String key = id + "::authz";
		String authz = (String) redisTemplate.opsForValue().get(key);
		AuthorizationVo authVo = null;
		if(authz == null) {
			
			authVo = new AuthorizationVo();
			authVo.setUserGroup(sqlSession.selectOne("getUserGroup", id));
			authVo.setRoleGroups(sqlSession.selectList("getRoleGroups", id));
			authVo.setRoles(sqlSession.selectList("getRoles", id));
			
			Gson gson = new Gson();
			authz = gson.toJson(authVo);
			
			redisTemplate.opsForValue().set(key, authz);
			
		}
		
		return authz;
		
	};
	
}