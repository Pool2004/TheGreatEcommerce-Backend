package com.ecommerce.Controller;


import com.ecommerce.Model.Dto.UsuarioModelDto;
import com.ecommerce.Service.ISecurityService;
import org.springframework.beans.factory.annotation.Autowired;
import com.ecommerce.Model.Dto.jwtResponseDTO;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/login")
public class AutheticationController {

    @Autowired
    ISecurityService securityService;

    @PostMapping("/log-in")
    public ResponseEntity<jwtResponseDTO> validarDatos(@RequestBody UsuarioModelDto usuario){

        jwtResponseDTO token = securityService.ingresarLogin(usuario);

        return new ResponseEntity<jwtResponseDTO>(token, HttpStatus.OK);
    }
}
