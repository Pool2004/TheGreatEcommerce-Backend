package com.ecommerce.Service;

import com.ecommerce.Model.*;
import com.ecommerce.Repository.ITelefonoUsuarioRepository;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;

import java.io.UncheckedIOException;
import java.util.List;
import java.util.Optional;

@Service
@Primary


public class TelefonoUsuarioServiceImp implements ITelefonoUsuarioService {

    @Autowired
    ITelefonoUsuarioRepository telefonoUsuarioRepository;

    private List<TelefonoUsuarioModel> telefonoUsuariosExistentes; // Se crea para mantener actualizado los datos entre bd y api

    @PostConstruct
    // PostConstructor, sirve para dar una INDICACIÓN luego de inicializar el main, por lo que al ejecutar esto se ejecutara.
    public void init(){ // Método públic, no devuelve nada (void) y de tipo init (inicializar algo)

        telefonoUsuariosExistentes= this.telefonoUsuarioRepository.findAll(); // Aca toma todas los articulos de la BD y las mete en el List.

    }
    @Override
    public String crearTelefonoUsuario(TelefonoUsuarioModel telefonoUsuario) {

        String textoRespuesta = "";

        try {
            UsuarioModel idUsuario = telefonoUsuario.getIdUsuario();
            Integer telefono = telefonoUsuario.getTelefono();

            telefonoUsuariosExistentes = this.telefonoUsuarioRepository.findAll();

            if (telefonoUsuariosExistentes.isEmpty()) {
                this.telefonoUsuarioRepository.save(telefonoUsuario);
                textoRespuesta = "El telefono del usuario ha sido creado con éxito.";
            } else {
                if (idUsuario == null) {
                    textoRespuesta += "El id de su usuario no puede ser nulo\n";
                }
                if (telefono == null) {
                    textoRespuesta += "El ID de la talla no puede ser nulo\n";
                }
                if (!textoRespuesta.isEmpty()) {
                    textoRespuesta += "Por favor, corrija los problemas y vuelva a intentarlo.\n";
                } else {
                    this.telefonoUsuarioRepository.save(telefonoUsuario);
                    textoRespuesta = "El telefono del usuario ha sido creado con éxito.";
                }
            }
        } catch (NullPointerException e) {
            textoRespuesta += "Tiene errores en el json\n";
        } catch (UncheckedIOException e) {
            textoRespuesta += "Errores\n";
        } catch (DataIntegrityViolationException e) {
            textoRespuesta += "Verifique si su usuario ya fue creado en la base de datos\n";
        }

        return textoRespuesta;
    }

    @Override
    public List<TelefonoUsuarioModel> listarTelefonoUsuario() {
        return this.telefonoUsuarioRepository.findAll();
    }

    @Override
    public Optional<TelefonoUsuarioModel> obtenerTelefonoUsuarioPorId(Integer idTelefonoUsuario) {
        return this.telefonoUsuarioRepository.findById(idTelefonoUsuario);
    }

    @Override
    public String actualizarTelefonoUsuarioPorId(TelefonoUsuarioModel telefonoUsuario, Integer idTelefonoUsuario) {

        String textoRespuesta = "";

        // Verificamos si existe para actualizar.
        try {
            Optional<TelefonoUsuarioModel> telefonoUsuarioEncontrado = this.telefonoUsuarioRepository.findById(idTelefonoUsuario);

            if (telefonoUsuarioEncontrado.isPresent()) {

                TelefonoUsuarioModel telefonoUsuarioActualizar = telefonoUsuarioEncontrado.get();

                BeanUtils.copyProperties(telefonoUsuario, telefonoUsuarioActualizar);

                this.telefonoUsuarioRepository.save(telefonoUsuarioActualizar);

                return "El telefono con código: " + idTelefonoUsuario + ", Ha sido actualizado con éxito.";

            } else {

                textoRespuesta = "El telefono con código: " + idTelefonoUsuario + ", No existe en el sistema. Por ende el proceso no se realizo correctamente.";
            }
        }catch(NullPointerException e){
            textoRespuesta = "Alguno de los valores son nulos, verifique los campos";
        }catch(UncheckedIOException e){
            textoRespuesta = "Se presento un error, inesperado. Verifique el JSON y los valores no puede ser nulos.";
        }catch(DataIntegrityViolationException e){
            textoRespuesta = "Un error en el JSON, verifique.";
        }

        return textoRespuesta;
    }
}
