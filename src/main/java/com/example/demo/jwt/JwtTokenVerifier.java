package com.example.demo.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.util.Strings;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class JwtTokenVerifier extends OncePerRequestFilter {
    
    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;

    public JwtTokenVerifier(SecretKey secretKey, JwtConfig jwtConfig) {
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        
        String authorizationHeader = request.getHeader(this.jwtConfig.getAuthorizationHeader());
        // System.out.println(authorizationHeader);
        // System.out.println(Strings.isNotEmpty(authorizationHeader));
        // System.out.println(!Strings.isNotEmpty(authorizationHeader) || !Strings.isNotBlank(authorizationHeader) || !authorizationHeader.startsWith("Bearer "));
        
        if (!Strings.isNotEmpty(authorizationHeader) || !Strings.isNotBlank(authorizationHeader) || !authorizationHeader.startsWith(this.jwtConfig.getTokenPrefix())) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authorizationHeader.replace(this.jwtConfig.getTokenPrefix(), "");
        try {

            Jws<Claims> claimsJws = Jwts.parser()
                    .verifyWith(this.secretKey)
                    .build()
                    .parseSignedClaims(token);
            
            Claims body = claimsJws.getPayload();
            String username = body.getSubject();
            var authorities = (List<Map<String, String>>)body.get("authorities");

            Set<SimpleGrantedAuthority> simpleGrantedAuthorities = authorities.stream()
                    .map(m -> new SimpleGrantedAuthority(m.get("authority")))
                    .collect(Collectors.toSet());

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    simpleGrantedAuthorities
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);

        } catch (JwtException e) {
            // TODO return 403
            // throw new IllegalStateException(String.format("Token %s cannot be trusted", token));
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Token non valide");
            return;
        }
        
        filterChain.doFilter(request, response);
    }
}
