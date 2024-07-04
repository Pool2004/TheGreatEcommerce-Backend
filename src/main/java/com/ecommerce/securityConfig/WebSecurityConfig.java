package com.ecommerce.securityConfig;


import com.ecommerce.Model.Enums.Roles;
import com.ecommerce.exception.AccesoNoAutorizadoWebException;
import com.ecommerce.security.JwtAuthenticactionFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

import static org.springframework.security.config.Customizer.withDefaults;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity

/**
 * Clase que configura lo relacionado a las peticiones HTTP
 */

public class WebSecurityConfig {

    private final AccesoNoAutorizadoWebException accesoNoAutorizadoWebException;

    private final JwtAuthenticactionFilter jwtAuthFilter;


    @Bean // Método que funciona como filtro para las solicitudes HTTP.
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception { // Aca llega el http

        http // Aca indica, a la petición que llegue mirele lo siguiente:
                .exceptionHandling().accessDeniedHandler(accesoNoAutorizadoWebException)
                .and()
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(solicitud ->// Aca indica, oiga antes de hacer cualquier cosa. Debe agregarse un filtro

                        solicitud

                                .requestMatchers("/login", "/log-in", "/login/log-in").permitAll() // Permite el acceso sin autenticación a las rutas que comienzan con ello.
                                .requestMatchers(HttpMethod.POST, "/login/log-in").permitAll()// Permitir el acceso al método POST desde la url.
                                .requestMatchers(HttpMethod.GET, "/get/**").hasAnyRole("Cliente", "Encargado")
                                .requestMatchers("/login/log-in").hasAnyAuthority(Roles.Cliente, Roles.Encargado) // Permitir a dicha URL teniendo alguno de los roles.
                                .anyRequest().authenticated()); // Cualquier otra petición debe estar autenticada , esto con el fin de que ya se haya verificado todo.



        return http.build(); // MÉTODO BUILD sirve para crear un objeto inmutable de la parte http.
    }

}
