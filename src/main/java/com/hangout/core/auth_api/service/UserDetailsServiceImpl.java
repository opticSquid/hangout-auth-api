package com.hangout.core.auth_api.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import com.hangout.core.auth_api.dto.event.AccountActivationMailEvent;
import com.hangout.core.auth_api.dto.event.VerifyAccountEvent;
import com.hangout.core.auth_api.dto.request.NewUser;
import com.hangout.core.auth_api.dto.request.UserValidationRequest;
import com.hangout.core.auth_api.dto.response.AccountVerficationResponse;
import com.hangout.core.auth_api.entity.Roles;
import com.hangout.core.auth_api.entity.User;
import com.hangout.core.auth_api.exceptions.JwtNotValidException;
import com.hangout.core.auth_api.exceptions.UserNotFoundException;
import com.hangout.core.auth_api.repository.UserRepo;

import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.instrumentation.annotations.WithSpan;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class UserDetailsServiceImpl implements UserDetailsService {
    @Autowired
    private UserRepo userRepo;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private KafkaTemplate<String, Object> eventBus;
    @Value("${hangout.kafka.topic.verification-mail}")
    private String verificationEmailTopic;
    @Autowired
    private RestClient restClient;
    @Value("${hangout.notification-service.url}")
    private String notificationService;
    @Value("${hangout.kafka.topic.activation-mail}")
    private String activationEmailTopic;

    @Override
    @WithSpan(value = "find user by username")
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> user = userRepo.findByUserName(username);
        if (user.isPresent()) {
            return org.springframework.security.core.userdetails.User.builder().username(user.get().getUsername())
                    .password(user.get().getPassword()).roles(user.get().getRole().name()).build();
        }
        throw new UsernameNotFoundException("User not found with username: " + username);
    }

    @WithSpan(kind = SpanKind.PRODUCER, value = "add new user")
    public void addNewUser(NewUser user) throws Exception {
        User newUser = new User(user.username(), user.email(), passwordEncoder.encode(user.password()));
        userRepo.save(newUser);
        // produce an event in kafka to send verification email
        eventBus.send(verificationEmailTopic, new VerifyAccountEvent(newUser.getUsername(), newUser.getEmail()));
    }

    @Transactional
    @WithSpan(kind = SpanKind.CLIENT, value = "verify user's email")
    public String verifyToken(String token) {
        try {
            ResponseEntity<AccountVerficationResponse> res = restClient
                    .post()
                    .uri(notificationService + "/verify-token")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(new UserValidationRequest(token))
                    .retrieve()
                    .toEntity(AccountVerficationResponse.class);
            log.debug("response recieved from notification service: {}", res);
            if (res != null && res.getBody().isVerified()) {
                log.debug("Token is verified: {}", res.getBody());
                log.debug("activating account");
                this.userRepo.activateAccount(res.getBody().email());
                Optional<User> user = this.userRepo.findByEmail(res.getBody().email());
                // produce an event in kafka to send account activation email
                log.debug("sending account activation mail");
                eventBus.send(activationEmailTopic,
                        new AccountActivationMailEvent(user.get().getUsername(), user.get().getEmail(), 200));
                return "account verified";
            } else {
                throw new JwtNotValidException("verification url is not valid");
            }
        } catch (RestClientResponseException ex) {
            throw new JwtNotValidException("verification url is not valid");
        } catch (Exception ex) {
            throw new UserNotFoundException("Account activation failed");
        }

    }

    @Transactional
    @WithSpan(value = "delete user's account")
    public void deleteUser(String username) throws Exception {
        this.userRepo.deleteByUserName(username);
    }

    public void addNewInternalUser(NewUser newUser) {
        User user = new User(newUser.username(), newUser.email(), passwordEncoder.encode(newUser.password()));
        user.setRole(Roles.INTERNAL);
        user.setEnabled(true);
        this.userRepo.save(user);
    }
}
