package jj.stella.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;

@Configuration
@EnableRedisRepositories
public class RedisConfig {

	@Autowired
	private Environment env;
	
	@Bean(name="redis")
	public RedisConnectionFactory redis() {
		
		RedisStandaloneConfiguration config = new RedisStandaloneConfiguration();
		config.setHostName(env.getProperty("spring.data.redis.host"));
		config.setPort(Integer.parseInt(env.getProperty("spring.data.redis.port")));
		config.setPassword(env.getProperty("spring.data.redis.password"));
		
		return new LettuceConnectionFactory(config);
		
	};
	
	@Bean
	public RedisTemplate<String, Object> redisTemplate() {
		
		RedisTemplate<String, Object> template = new RedisTemplate<>();
		
		template.setConnectionFactory(redis());
		template.setKeySerializer(new StringRedisSerializer());
		template.setValueSerializer(new GenericJackson2JsonRedisSerializer());
		template.setHashKeySerializer(new StringRedisSerializer());
		template.setHashValueSerializer(new GenericJackson2JsonRedisSerializer());
		
		return template;
		
	};
	
	/**
	 * 예제코드
	 * - Controller에서 @Cacheable 사용할 때
	 * @Cacheable(cacheManager="...", value="...", key="...")
	 * 이런 식으로 사용하게 되는데, 이 때 cacheManager에 cacheManager12H, cacheManager1H 이런식으로 설정하게되면
	 * TTL이 자동으로 설정됨
	 * 
	 * ex. @Cacheable(cacheManager="cacheManager12H", value="...", key="...")
	 * ( 필요하면 사용하는데, RedisUtil만들어서 사용하는게 더 편해서 사용안하는 중 )
	 * 
	@Bean
	@Primary
	public CacheManager cacheManager(RedisConnectionFactory connectionFactory) {
		
		RedisCacheConfiguration redisCacheConfiguration = 
				RedisCacheConfiguration.defaultCacheConfig()
				.serializeKeysWith(
					RedisSerializationContext.SerializationPair.fromSerializer(
						new StringRedisSerializer()
					)
				);
		
		return RedisCacheManager
				.RedisCacheManagerBuilder
				.fromConnectionFactory(connectionFactory)
				.cacheDefaults(redisCacheConfiguration)
				.build();
		
	};
	
	// TTL 12시간
	@Bean
	public CacheManager cacheManager12H(RedisConnectionFactory connectionFactory) {
		
		RedisCacheConfiguration redisCacheConfiguration = 
				RedisCacheConfiguration.defaultCacheConfig()
				.serializeKeysWith(
					RedisSerializationContext.SerializationPair.fromSerializer(
						new StringRedisSerializer()
					)
				).entryTtl(Duration.ofHours(12));
		
		return RedisCacheManager
				.RedisCacheManagerBuilder
				.fromConnectionFactory(connectionFactory)
				.cacheDefaults(redisCacheConfiguration)
				.build();
		
	};
	
	// TTL 1시간
	@Bean
	public CacheManager cacheManager1H(RedisConnectionFactory connectionFactory) {
		
		RedisCacheConfiguration redisCacheConfiguration = 
				RedisCacheConfiguration.defaultCacheConfig()
				.serializeKeysWith(
					RedisSerializationContext.SerializationPair.fromSerializer(
						new StringRedisSerializer()
					)
				).entryTtl(Duration.ofHours(1));
		
		return RedisCacheManager
				.RedisCacheManagerBuilder
				.fromConnectionFactory(connectionFactory)
				.cacheDefaults(redisCacheConfiguration)
				.build();
		
	};
	 */
	
}