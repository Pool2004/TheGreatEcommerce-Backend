package com.ecommerce.Service;

import com.ecommerce.Model.Dto.UsuarioModelDto;
import com.ecommerce.Model.Dto.jwtResponseDTO;
import com.ecommerce.Model.UsuarioModel;
import com.ecommerce.Repository.IUsuarioRepository;
import com.ecommerce.security.JwtAuthenticactionProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;


@Service
public class SecurityServiceImp implements ISecurityService{


    @Autowired
    JwtAuthenticactionProvider authenticactionProvider;

    @Autowired
    IUsuarioRepository usuarioRepository;
    @Override
    public jwtResponseDTO ingresarLogin(UsuarioModelDto usuarioModelDto){ // Este va a ser el primero que se manda, correo y contraseña antes de generar el token

        Optional<UsuarioModel> usuario = usuarioRepository.findUsuarioModelByCorreo(usuarioModelDto.getCorreo());
        UsuarioModel objU = new UsuarioModel();

        if(usuario.isEmpty()){

            System.out.println("Usuario No existente.");

        }else{

            objU = usuario.get();

        }

        if(!objU.getContrasenia().matches(usuarioModelDto.getContrasenia())){

            System.out.println("Contraseña incorrecta");

        }

        return new jwtResponseDTO(authenticactionProvider.crearToken(objU)); // Crea un obj de respuesta con DTO (solo string token y almacena lo que devuelva el token creado)
    }

    @Override
    public jwtResponseDTO cerrarsesion(String token) {

        String[] authElements = token.split(" "); // Aca divide el token en 2 (Bearer [0] , token [1]
        return new jwtResponseDTO(authenticactionProvider.borrartoken(authElements[1]));
    }

}
