package com.ecommerce.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.ecommerce.Model.UsuarioModel;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;


@Component
public class JwtAuthenticactionProvider {


    @Value("SaraSofiaVolveras")
    private String llaveSecreta;

    private HashMap<String, UsuarioModel> listaBlanca = new HashMap<>();

    public String crearToken(UsuarioModel usuario){

        // Obtiene objeto fecha para creación del token
        Date fecha = new Date();
        // Obtener ahora la fecha de la creación
        Date validacion = new Date(fecha.getTime() + 3600000); // Aca obtenemos la fecha y le agregamos el tiempo de validación


        Algorithm algoritmo = Algorithm.HMAC256(llaveSecreta); // Aca creamos una clase algoritmo y aplicamos la encriptación con el algoritmo HMAC256 a llave secreta

        String tokenCreado = JWT.create()
                .withClaim("nombre", usuario.getNombre())
                .withClaim("telefono", String.valueOf(usuario.getTelefono())) // Como el token es STRING debemos castear todos los datos a este
                .withClaim("correo", usuario.getCorreo())
                .withClaim("rol", usuario.getRol().name())
                .withClaim("sexo", usuario.getSexo().name())
                .withClaim("identificacion", String.valueOf(usuario.getIdentificacion()))
                .withIssuedAt(fecha) // Con fecha de creación
                .withExpiresAt(validacion) // Con fecha de expiración
                .sign(algoritmo);// El withClaim indica los atributos que van a ir del JWT en este caso, pues que tanto queremos meter de usuario.
        listaBlanca.put(tokenCreado, usuario); // Aca creamos un hasmap (Lista clave- valor) la clave será el token y el usuario los datos del uaurio (obj)
        return tokenCreado;

    }

    public Authentication validarToken(String token) throws AuthenticationException { // Devuelve un objeto de autenticación, recuerda que el manager usa el objeto del token para ello

        System.out.println("Entro aca");
        System.out.println("El token es: " + token);

        JWT.require(Algorithm.HMAC256(llaveSecreta)).build().verify(token);
        // Aca el JWT crea de nuevo el algoritmo y encripta la firma, luego crea la instancia del verify y lo verifica
        // con la firma del Token, a ver si es la misma y no se ha modificado.

        // El verify , verifica: Que exista, que sea correcto, que sea igual, que no haya exípirado, etc.

        // Verificamos la lista blanca si esta el token que llego

        UsuarioModel objU = listaBlanca.get(token); // Aca según el token del http que llego si esta en la lista blanca, pa dentro
        System.out.println("objeto recuperado" + objU.toString());
        if(objU == null){

            System.out.println("Acceso Invalido: No aparece en la whitelist");
        }


        HashSet<SimpleGrantedAuthority> rolesAutorizaciones = new HashSet<>();
        rolesAutorizaciones.add(new SimpleGrantedAuthority("ROLE_"+objU.getRol().name())); //rol

        return new UsernamePasswordAuthenticationToken(objU, token, rolesAutorizaciones); // DEBE ir los roles o autorizaciones corredspondientes.

    }

    public String borrartoken(String token){

        if (!listaBlanca.containsKey(token)) {
            return "No existe token";
        }

        listaBlanca.remove(token);
        return "Sesión cerrada exitosamente";

    }
}
