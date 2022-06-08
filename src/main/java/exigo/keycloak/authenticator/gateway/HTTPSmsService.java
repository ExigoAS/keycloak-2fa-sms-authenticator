package exigo.keycloak.authenticator.gateway;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.mime.MultipartEntityBuilder;
import twitter4j.JSONObject;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class HTTPSmsService implements SmsService {
	private final String senderId;
	private final String urlDestination;

	private final String clientId;
	private final String clientSecret;
	private final String tokenUrl;
	private final String username;
	private final String password;

	HTTPSmsService(Map<String, String> config) {
		senderId = config.get("senderId");
		urlDestination = config.get("urlDestination");

		clientId = config.get("clientId");
		clientSecret = config.get("clientSecret");
		tokenUrl = config.get("tokenUrl");
		username = config.get("username");
		password = config.get("password");
	}

	@Override
	public void send(String phoneNumber, String message) {

		String urlFormatted = String.format(urlDestination, senderId, message);
		try {
			Map<String, String> parameters = new HashMap<>();
			parameters.put("grant_type", "password");
			parameters.put("client_id", clientId);
			parameters.put("client_secret", clientSecret);
			parameters.put("username", username);
			parameters.put("password", password);
			parameters.put("scope", "openid email");

			String form = parameters.entrySet()
				.stream()
				.map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
				.collect(Collectors.joining("&"));

			// Get Access Token
			URI tokenUri = URI.create(tokenUrl);
			var tokenClient = HttpClient.newHttpClient();

			var tokenRequest = HttpRequest.newBuilder(tokenUri)
				.headers("Content-Type", "application/x-www-form-urlencoded")
				.POST(HttpRequest.BodyPublishers.ofString(form))
				.build();

			var tokenResponse = tokenClient.send(tokenRequest, HttpResponse.BodyHandlers.ofString());
			ObjectMapper mapper = new ObjectMapper();
			var tokenMap = mapper.readValue(tokenResponse.body(), Map.class);
			var accessToken = tokenMap.get("access_token");

			// Send SMS Request
			var formatRequest = "{ \"phoneNumber\": \"%s\", \"message\": \"%s\" }";
			var formattedRequest = String.format(formatRequest, phoneNumber, message);

			URI url = URI.create(urlFormatted);
			var client = HttpClient.newHttpClient();
			var request = HttpRequest.newBuilder(url)
				.header("Authorization", "Bearer " + accessToken)
				.headers("Content-Type", "application/json")
				.POST(HttpRequest.BodyPublishers.ofString(formattedRequest))
				.build();

			client.send(request, HttpResponse.BodyHandlers.ofString());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
