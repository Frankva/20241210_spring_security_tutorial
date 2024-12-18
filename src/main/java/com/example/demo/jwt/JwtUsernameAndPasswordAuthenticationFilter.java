package com.example.demo.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.time.LocalDate;
import java.util.Date;



public class JwtUsernameAndPasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final JwtConfig jwtConfig;
    private final SecretKey secretKey;

    public JwtUsernameAndPasswordAuthenticationFilter(AuthenticationManager authenticationManager,
                                                      JwtConfig jwtConfig,
                                                      SecretKey secretKey) {
        
        this.authenticationManager = authenticationManager;
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        try {
            UsernameAndPasswordAuthenticationRequest authenticationRequest = new ObjectMapper().readValue(request.getInputStream(), UsernameAndPasswordAuthenticationRequest.class);
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getUsername(),
                    authenticationRequest.getPassword()
            );

            Authentication authenticate = this.authenticationManager.authenticate(authentication);
            
            String token = this.getToken(authenticate);

            response.addHeader(this.jwtConfig.getAuthorizationHeader(), this.jwtConfig.getTokenPrefix() + token);
            
            return authenticate;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    
    protected String getToken(Authentication authResult) {

        String token = Jwts.builder()
                .subject(authResult.getName())
                .claim("authorities", authResult.getAuthorities())
                .issuedAt(new Date())
                .expiration(java.sql.Date.valueOf(LocalDate.now().plusDays(this.jwtConfig.getTokenExpirationAfterDays())))
                .signWith(this.secretKey)
                .compact();
        
        return token;
    }

    //@Override
    //protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
    //    super.successfulAuthentication(request, response, chain, authResult);
    //    String key = "jljrewuionjr7392ujjvmayrjmfuj8793ujlkcuiourufvmsr823urydhcnskjfjlabananekeuru8347cruieurouweoruoewuriouufudisuofaudmjjijofjasjer231e";

    //    String token = Jwts.builder()
    //            .subject(authResult.getName())
    //            .claim("authorities", authResult.getAuthorities())
    //            .issuedAt(new Date())
    //            .expiration(java.sql.Date.valueOf(LocalDate.now().plusWeeks(2)))
    //            .signWith(Keys.hmacShaKeyFor(key.getBytes()))
    //            .compact();

    //    response.addHeader("Authorization", "Bearer " + token);
    //    response.setHeader("Authorization", "Bearer " + token);
    //    chain.doFilter(request, response);
    //}
    
}
