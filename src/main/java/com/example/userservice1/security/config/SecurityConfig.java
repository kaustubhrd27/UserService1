package com.example.userservice1.security.config;

import com.example.userservice1.security.Models.CustomUserDetails;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
public class SecurityConfig {



    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0
        http
                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                // Accept access tokens for User Info and/or Client Registration
                .oauth2ResourceServer((resourceServer) -> resourceServer
                        .jwt(Customizer.withDefaults()));

        return http.build();
    }



    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        // This filter chain applies to all URLs not covered by
        // the OAuth 2.0 Authorization Server configuration (which had higher priority at Order(1)).
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().permitAll()
                )
                .cors().disable()
                .csrf().disable()
                // Form login handles the redirect to the login page from the
                // authorization server filter chain
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

//    @Bean
//    public UserDetailsService userDetailsService() {
//        UserDetails userDetails = User.builder()
//                .username("user")
//                .password("$2a$12$MbfOjGTBFanotv281YCXEeTbfPJ6IeVlt12806ojwzHNY.nQxmvxS")
//                .roles("USER")
//                .build();
//
//        return new InMemoryUserDetailsManager(userDetails);
//    }

//    @Bean
//    // RegisteredClientRepository -->>  is a repository interface in Spring Security
//    // that holds the registered clients for OAuth 2.0 operations.
//    public RegisteredClientRepository registeredClientRepository() {
//        // This method defines a Spring Security bean for registering a client in an OAuth 2.0 Authorization Server.
//        // The client in this context represents an external application (or service)
//        // that can interact with your authorization server to authenticate users and obtain tokens.
//        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
//        // Each client must have a unique ID. In this case, a random UUID is generated as the client’s ID.
//                .clientId("oidc-client")
//                // The client ID uniquely identifies the client to the authorization server.
//                // Here, the client ID is set to "oidc-client".
//                .clientSecret("{noop}secret")
//                //The client secret is like a password that the client uses to authenticate with the authorization server.
//                //{noop} is used to indicate that the secret is not encoded (this is used for testing or development).
//                // In production, this should be encoded using a secure algorithm (e.g., BCrypt).
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                //Specifies the authorization grant type as authorization code.
//                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//                // GrantType for refreshing the token
//                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client")
//                //After successful authorization, the authorization server will redirect the user to this URL,
//                // including the authorization code
//                .postLogoutRedirectUri("http://127.0.0.1:8080/")
//                .scope(OidcScopes.OPENID)
//                //Roles
//                .scope(OidcScopes.PROFILE)
//                .scope("ADMIN")
//                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
//                .build();
//
//        return new InMemoryRegisteredClientRepository(oidcClient);
//    }


    // This method defines a JWK (JSON Web Key) source that will be used for JWT (JSON Web Token)
    // signing and verification in an OAuth 2.0 or OpenID Connect (OIDC) authorization server setup.
    // It generates an RSA key pair and registers it as part of a JWKSet to be used for secure communication.
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
// JWKSource: It stands for JSON Web Key Source, which is a collection of public and private keys.
// These keys are used by an authorization server for signing and verifying JWTs (usually access tokens and ID tokens)
        KeyPair keyPair = generateRsaKey();
//RSA (Rivest-Shamir-Adleman) is an asymmetric encryption algorithm,which means it uses a public key for encryption
// and a private key for decryption. Here, an RSA key pair is generated, consisting of:
//A public key used for verifying tokens.
//A private key used for signing tokens
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    // Generates RSA Key (Basically We can say it is like secret key)
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }


    // JwtDecoder: This is an interface provided by Spring Security, which is responsible for decoding JWTs.
    // It can validate the signature of the JWT and extract the claims from it.
    // The JwtDecoder will utilize the public keys from the provided JWK source to validate the JWT's signature.
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return (context) -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType()))
            // This checks if the token being customized is an Access Token.
            // Access tokens are used to grant access to protected resources.
            // The token customization will only happen if this condition is true.
            {
                context.getClaims().claims((claims) -> {
                    // This modifies the claims section of the JWT. Claims are pieces of information that the JWT contains,
                    // such as user information or roles. In this case, we’re adding a new claim named roles.
                    Set<String> roles = AuthorityUtils.authorityListToSet(context.getPrincipal().getAuthorities())
                            // The context.getPrincipal() retrieves the authenticated user (the principal).
                            // getAuthorities() returns the roles or authorities assigned to this user.
                            .stream()
                            .map(c -> c.replaceFirst("^ROLE_", ""))
                            .collect(Collectors.collectingAndThen(Collectors.toSet(), Collections::unmodifiableSet));
                    claims.put("roles", roles);
                    claims.put("userId", ((CustomUserDetails)context.getPrincipal().getPrincipal()).getUserId());
                    claims.put("userId", ((CustomUserDetails)context.getPrincipal().getPrincipal()).getUserName());
                });
            }
        };
    }
}

