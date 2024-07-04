package com.ecommerce.Service;
import com.ecommerce.Model.Dto.UsuarioModelDto;
import com.ecommerce.Model.Dto.jwtResponseDTO;
public interface ISecurityService {

    public jwtResponseDTO ingresarLogin(UsuarioModelDto usuarioModelDto);

    public jwtResponseDTO cerrarsesion(String token);


}
