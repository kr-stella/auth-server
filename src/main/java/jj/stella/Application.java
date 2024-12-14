package jj.stella;

import java.util.Map;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;

@SpringBootApplication
public class Application extends SpringBootServletInitializer {
	
	public static void main(String[] args) throws Exception {
		
		Region region = Region.AP_NORTHEAST_2;
		String secret = System.getenv("ST2LLA_PROPS");
		ProfileCredentialsProvider provider = ProfileCredentialsProvider.builder()
			.profileName("default")
			.build();
		
		SecretsManagerClient client = SecretsManagerClient.builder()
				.region(region)
				.credentialsProvider(provider)
				.build();
		
		GetSecretValueRequest request = GetSecretValueRequest.builder()
			.secretId(secret)
			.build();
		
		String value = client.getSecretValue(request).secretString();
//		GetSecretValueResponse getSecretValueResponse = client.getSecretValue(request);
//		System.out.println("====== getSecretValueResponse ======");
//		System.out.println(getSecretValueResponse.secretString());
		
		ObjectMapper object = new ObjectMapper();
		TypeReference<Map<String, String>> type = new TypeReference<Map<String, String>>() {};
		Map<String, String> secrets = object.readValue(value, type);
		for(Map.Entry<String, String> entry:secrets.entrySet())
			System.setProperty(entry.getKey(), entry.getValue());
		
		// 환경변수 확인하려면 주석 풀기
//		secrets.forEach((key, val) -> System.out.println("Loaded secret: " + key + " = " + val));
		System.setProperty("server.servlet.context-path", "/");
		SpringApplication.run(Application.class, args);
		
	}
	
	@Override
	protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
		return application.sources(Application.class);
	}
	
}