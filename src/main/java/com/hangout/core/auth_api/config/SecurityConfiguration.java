package com.hangout.core.auth_api.config;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.hangout.core.auth_api.entity.Roles;
import com.hangout.core.auth_api.filter.JwtFilter;
import com.hangout.core.auth_api.filter.UserAuthenticationFilter;
import com.hangout.core.auth_api.service.UserDetailsServiceImpl;

import lombok.extern.slf4j.Slf4j;

@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfiguration {
	@Autowired
	private UserDetailsServiceImpl userDetailsService;
	@Autowired
	private JwtFilter jwtFilter;
	@Autowired
	private UserAuthenticationFilter userAuthenticationFilter;
	@Autowired
	PasswordEncoder passwordEncoder;
	@Value("${hangout.internal-services.origin}")
	private String internalServicesOrigins;
	@Value("${hangout.client.origin}")
	private String clientOrigins;

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http)
			throws Exception {
		http
				.cors(c -> c.configurationSource(myCorsConfigurationSource()))
				.csrf(csrf -> csrf.disable())
				.authorizeHttpRequests(auth -> auth
						.requestMatchers("/v1/user/**")
						.authenticated()
						.requestMatchers("/v1/admin/**").hasRole(Roles.ADMIN.name())
						.requestMatchers(CorsUtils::isPreFlightRequest).permitAll() // Allow OPTIONS for CORS preflight
						.anyRequest().permitAll() // All other requests are permitted
				)
				.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
				.addFilterBefore(userAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

		return http.build();
	}

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
	}

	@Bean
	AuthenticationManager authenticationManager(AuthenticationConfiguration auth)
			throws Exception {
		return auth.getAuthenticationManager();
	}

	CorsConfigurationSource myCorsConfigurationSource() {
		CorsConfiguration clientConfiguration = new CorsConfiguration();
		CorsConfiguration internalServiceConfiguration = new CorsConfiguration();
		// parsing comma seperated string to a list
		List<String> allowedClientOriginList = Arrays.stream(clientOrigins.split(",")).map(String::trim)
				.collect(Collectors.toList());
		List<String> allowedInternalOriginsList = Arrays.stream(internalServicesOrigins.split(",")).map(String::trim)
				.collect(Collectors.toList());
		log.info("Allowed client origins: {}, allowed internal service origins: {}", clientOrigins,
				allowedInternalOriginsList);
		clientConfiguration.setAllowedOriginPatterns(allowedClientOriginList);
		internalServiceConfiguration.setAllowedOriginPatterns(allowedInternalOriginsList);
		clientConfiguration.setAllowedHeaders(Arrays.asList("*"));
		internalServiceConfiguration.setAllowedHeaders(Arrays.asList("*"));
		clientConfiguration
				.setAllowedMethods(
						Arrays.asList(
								HttpMethod.OPTIONS.name(),
								HttpMethod.GET.name(),
								HttpMethod.POST.name(),
								HttpMethod.DELETE.name()));
		internalServiceConfiguration
				.setAllowedMethods(Arrays.asList(HttpMethod.OPTIONS.name(), HttpMethod.POST.name()));
		clientConfiguration.setAllowCredentials(true);
		internalServiceConfiguration.setAllowCredentials(false);
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.setCorsConfigurations(Map.of(
				"/v1/auth/**", clientConfiguration,
				"/v1/user/**", clientConfiguration,
				"/v1/internal/**", internalServiceConfiguration,
				"/v1/admin/**", internalServiceConfiguration));
		return source;
	}
}
