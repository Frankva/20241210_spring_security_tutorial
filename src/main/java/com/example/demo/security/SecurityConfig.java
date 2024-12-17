package com.example.demo.security;

import com.example.demo.auth.ApplicationUserService;
import com.example.demo.jwt.JwtTokenVerifier;
import com.example.demo.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.StaticHeadersWriter;

import static com.example.demo.security.ApplicationUserRole.*;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity // for activate @PreAuthorize
public class SecurityConfig {

   private final PasswordEncoder passwordEncoder;
   private final ApplicationUserService applicationUserService;

   public SecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService) {
       this.passwordEncoder = passwordEncoder;
       this.applicationUserService = applicationUserService;
   }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.headers(a -> a.addHeaderWriter(new StaticHeadersWriter("a", "b")));
        http
           // .csrf((csrf) -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
            .csrf((csrf) -> csrf.disable())
            .sessionManagement(session -> session
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager()))
            .addFilterAfter(new JwtTokenVerifier(), JwtUsernameAndPasswordAuthenticationFilter.class)
            .authorizeHttpRequests((requests) -> requests
                .requestMatchers("/", "/css/*", "/js/*").permitAll()
                .requestMatchers("/api/**").hasRole(STUDENT.name())
                // replace by @PreAuthorize in controller
                // .requestMatchers(HttpMethod.DELETE, "management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                // .requestMatchers(HttpMethod.POST,"management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                // .requestMatchers(HttpMethod.PUT, "management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                // .requestMatchers(HttpMethod.GET, "management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
                .anyRequest().permitAll()
            );
                // .httpBasic(Customizer.withDefaults());
                //.formLogin(Customizer.withDefaults());
        return http.build();
    }

    // @Bean
    // public UserDetailsService userDetailsService() {
    //     UserDetails userDetails = User.builder()
    //             .username("annasmith")
    //             .password(passwordEncoder.encode("password"))
    //             // .roles(STUDENT.name()) // ROLE_STUDENT
    //             .authorities(STUDENT.getGrantedAuthorities())
    //             .build();

    //     UserDetails lindaUser = User.builder()
    //             .username("linda")
    //             .password(passwordEncoder.encode("password"))
    //             // .roles(ADMIN.name()) // ROLE_ADMIN
    //             .authorities(ADMIN.getGrantedAuthorities())
    //             .build();

    //     UserDetails tomUser = User.builder()
    //             .username("tom")
    //             .password(passwordEncoder.encode("password"))
    //             // .roles(ADMINTRAINEE.name()) // ROLE_ADMINTRAINEE
    //             .authorities(ADMINTRAINEE.getGrantedAuthorities())
    //             .build();

    //     return new InMemoryUserDetailsManager(userDetails, lindaUser, tomUser);
    // }


    @Bean
    public AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(this.applicationUserService);
        authenticationProvider.setPasswordEncoder(this.passwordEncoder);

        return new ProviderManager(authenticationProvider);
    }
    
}
