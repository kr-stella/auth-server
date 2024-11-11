//package jj.stella.repository.service;
//
//import java.util.concurrent.TimeUnit;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.data.redis.core.RedisTemplate;
//import org.springframework.stereotype.Service;
//
//@Service
//public class RedisServiceImpl implements RedisService {
//	
//	private final RedisTemplate<String, Object> redisTemplate;
//	
//	@Autowired
//	public RedisServiceImpl(RedisTemplate<String, Object> redisTemplate) {
//		this.redisTemplate = redisTemplate;
//	}
//	
//	@Override
//	public <T> T getFromCache(String key, Class<T> type) {
//		return type.cast(redisTemplate.opsForValue().get(key));
//	}
//	
//	@Override
//	public <T> void cacheData(String key, T data, long timeout, TimeUnit unit) {
//		redisTemplate.opsForValue().set(key, data, timeout, unit);
//	}
//	
//}