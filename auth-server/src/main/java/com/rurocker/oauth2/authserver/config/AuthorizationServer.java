package com.rurocker.oauth2.authserver.config;

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@SuppressWarnings("deprecation")
@Configuration
@EnableAuthorizationServer
public class AuthorizationServer extends AuthorizationServerConfigurerAdapter implements ApplicationContextAware {

    private static final String JWT_SIGNING_KEY = "JWT_SIGNING_KEY";
    private static final String CLIENT = "ru-rocker";
    private static final String IMPLICIT = "implicit";
    private static final String REFRESH_TOKEN = "refresh_token";
    private static final String AUTHORIZATION_CODE = "authorization_code";
    private static final String PASSWORD = "password";
    private static final String SECRET = "secret";
    private static final String REALM = "DEMO_REALM";
    private static final String[] SCOPES = { "read", "write" };

    // Access token is only valid for 30 minutes.
    private static final int ACCESS_TOKEN_VALIDITY_SECONDS = 1800;

    // Refresh token is only valid for 60 minutes.
    private static final int REFRESH_TOKEN_VALIDITY_SECONDS = 3600;

    ApplicationContext applicationContext;

    @Autowired
    @Qualifier("authenticationManagerBean")
    private AuthenticationManager authenticationManager;

    @Override
    public void configure(final ClientDetailsServiceConfigurer clients) throws Exception {

    		// @formatter:off
        clients.inMemory()
        		   .withClient(CLIENT)
               .authorizedGrantTypes(PASSWORD, AUTHORIZATION_CODE, REFRESH_TOKEN, IMPLICIT)
               .scopes(SCOPES)
               .secret(this.passwordEncoder().encode(SECRET))
               .accessTokenValiditySeconds(ACCESS_TOKEN_VALIDITY_SECONDS)
               .refreshTokenValiditySeconds(REFRESH_TOKEN_VALIDITY_SECONDS);
        // @formatter:on
    }

    /**
     * Apply the token converter (and enhancer) for token store.
     *
     * @return the JwtTokenStore managing the tokens.
     */
    @Bean
    public JwtTokenStore tokenStore() {
        return new JwtTokenStore(this.jwtAccessTokenConverter());
    }

    /**
     * This bean generates an token enhancer, which manages the exchange between JWT access tokens and Authentication
     * in both directions.
     *
     * @return an access token converter configured with the authorization server's public/private keys
     */
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        final JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigningKey(JWT_SIGNING_KEY);
        return converter;
    }
    
	@Bean
    public PasswordEncoder passwordEncoder() {
    		// on purpose using NoOpPasswordEncoder for demo
    		// can use BCrypt or other encoder
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    public void configure(final AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        final Collection<TokenEnhancer> tokenEnhancers = applicationContext.getBeansOfType(TokenEnhancer.class)
                .values();
        final TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(new ArrayList<>(tokenEnhancers));

        // @formatter:off
        endpoints.tokenStore(this.tokenStore())
                 .accessTokenConverter(this.jwtAccessTokenConverter())
                 .authenticationManager(authenticationManager)
                 .tokenEnhancer(tokenEnhancerChain);
        // @formatter:on
    }

    @Override
    public void configure(final AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer.realm(REALM + "/client");
    }

    @Override
    public void setApplicationContext(final ApplicationContext applicationContext) throws BeansException {
        this.applicationContext = applicationContext;
    }
}