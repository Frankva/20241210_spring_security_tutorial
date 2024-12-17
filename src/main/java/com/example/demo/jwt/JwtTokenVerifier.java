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

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class JwtTokenVerifier extends OncePerRequestFilter {
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        
        String authorizationHeader = request.getHeader("Authorization");
        // System.out.println(authorizationHeader);
        // System.out.println(Strings.isNotEmpty(authorizationHeader));
        // System.out.println(!Strings.isNotEmpty(authorizationHeader) || !Strings.isNotBlank(authorizationHeader) || !authorizationHeader.startsWith("Bearer "));
        
        if (!Strings.isNotEmpty(authorizationHeader) || !Strings.isNotBlank(authorizationHeader) || !authorizationHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authorizationHeader.replace("Bearer ", "");
        try {
            String secretKey = "jljrewuionjr7392ujjvmayrjmfuj8793ujlkcuiourufvmsr823urydhcnskjfjlabananekeuru8347cruieurouweoruoewuriouufudisuofaudmjjijofjasjer231e";

            Jws<Claims> claimsJws = Jwts.parser()
                    .verifyWith(Keys.hmacShaKeyFor(secretKey.getBytes()))
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
