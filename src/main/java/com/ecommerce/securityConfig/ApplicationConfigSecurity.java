package com.ecommerce.securityConfig;


import com.ecommerce.security.JwtAuthenticactionFilter;
import com.ecommerce.security.JwtAuthenticactionProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;


@RequiredArgsConstructor // Indica se utiliza para generar un constructor con parámetros para todas las variables de instancia final y las que están anotadas con @NonNull
@Configuration // Indica que Spring, apenas ejecute lea esta clase para establecer ciertas reglas.
public class ApplicationConfigSecurity {

    private final JwtAuthenticactionProvider jwtAuthenticactionProvider;


    @Bean
    public JwtAuthenticactionFilter jwtAuthFilter() {
        return new JwtAuthenticactionFilter(jwtAuthenticactionProvider);
    }




}
