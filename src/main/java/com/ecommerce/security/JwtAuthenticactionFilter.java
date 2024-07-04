package com.ecommerce.security;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@RequiredArgsConstructor

public class JwtAuthenticactionFilter extends  OncePerRequestFilter{ // Hereda de cada petición aplicarle un filtro.

    private final JwtAuthenticactionProvider jwtAuthenticactionProvider;
    private List<String> UrisPermitidas = List.of("/login", "/log-in", "/login/log-in"); // Lista de URL a las que no se le aplican el filtro.


    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        System.out.println("en esta peticion se rompe");
        System.out.println(request.getRequestURI());
        System.out.println("Entro al filtro :)");
        return UrisPermitidas.stream().anyMatch(url -> request.getRequestURI().contains(url)); // Devuelve un booleano, para ver si se le aplica o no el filtro.

    }

    @Override
    protected void doFilterInternal(HttpServletRequest httpRequest, HttpServletResponse respuesta, FilterChain filtro) throws ServletException, IOException {


        String header = httpRequest.getHeader(HttpHeaders.AUTHORIZATION); // Aca del Http con el token que llegue toma el header a ver si está autorizado.

        if(header == null){

            System.out.println("El header es nulo, acceso invalido");
        }

        String[] elementosAutenticacion = header.split(" "); // Aca el http (Token) se divide por parte, quedando el header y el token en una lista de tipo String


        if(elementosAutenticacion.length != 2 || !"Bearer".equals(elementosAutenticacion[0])){
        // La autenticación correcta quedaria en 2 partes, si supera 2 ya hay un problema y si no hay un Bearer es decir que el token no es valid
            // Tengamos en cuenta que en la posición 0 es el Bearer 1 el token.
            System.out.println("Acceso invalido, header erroneo o longitud aut extendida");
        }

        // Si en los dos casos, no se cumplieron el token es correcto. Por lo que validaremos


        try{
            System.out.println("entro al try");
            Authentication auth = jwtAuthenticactionProvider.validarToken(elementosAutenticacion[1]);
            System.out.println("volvio bien");
            SecurityContextHolder.getContext().setAuthentication(auth); // Esto permite que la información de autenticación esté disponible en cualquier parte de la aplicación que necesite verificar la autenticación del usuario o sus roles/permisos.
            System.out.println("se autorizo");
            System.out.println("El holder es" + SecurityContextHolder.getContext());
            // ... ACA ES LA AUTENTICACIÓN ARRIBA
        }catch (RuntimeException e) {
            SecurityContextHolder.clearContext(); // Limpiamos para evitar que se sobreescriban datos en la próxima verificación
            System.out.println("se estalló");
            System.out.println(e);
            throw new RuntimeException(e);
        }

        filtro.doFilter(httpRequest, respuesta); // Aca al fintro le hacemos una petición con los datos de la http request y la respuesta.

    }


}
