package com.ecommerce.Service;


import com.ecommerce.Model.ArticuloModel;
import com.ecommerce.Model.Enums.Talla;
import com.ecommerce.Model.TallaModel;

import com.ecommerce.Repository.ITallaRepository;
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

public class TallaServiceImp implements ITallaService {

    @Autowired
    ITallaRepository tallaRepository;

    private List<TallaModel> tallasExistentes; // Se crea para mantener actualizado los datos entre bd y api

    @PostConstruct
    // PostConstructor, sirve para dar una INDICACIÓN luego de inicializar el main, por lo que al ejecutar esto se ejecutara.
    public void init(){ // Método públic, no devuelve nada (void) y de tipo init (inicializar algo)

        tallasExistentes= this.tallaRepository.findAll(); // Aca toma todas los articulos de la BD y las mete en el List.

    }

    @Override
    public String crearTalla(TallaModel talla) {

        String textoRespuesta = "";

        try {
            Talla nombreT = talla.getTalla();


            tallasExistentes = this.tallaRepository.findAll();
            if (nombreT == null) {
                textoRespuesta += "El nombre de la talla no puede ser nulo\n";
            }
            if (!textoRespuesta.isEmpty()) {
                textoRespuesta += "Por favor, corrija los problemas y vuelva a intentarlo.\n";
            }else{


                if (tallasExistentes.isEmpty()) {
                    this.tallaRepository.save(talla);
                    textoRespuesta = "La talla ha sido creada con éxito.";
                }else {
                    this.tallaRepository.save(talla);
                    textoRespuesta = "La talla ha sido creada con éxito.";
                }
            }
        } catch (NullPointerException e) {
            textoRespuesta += "Algún valor es nulo\n";
        } catch (UncheckedIOException e) {
            textoRespuesta += "Errores\n";
        } catch (DataIntegrityViolationException e) {
            textoRespuesta += "Verifique los valores y vuelva a probar\n";
        }

        return textoRespuesta;
    }
    @Override
    public List<TallaModel> listarTalla() {
        return this.tallaRepository.findAll();
    }

    @Override
    public Optional<TallaModel> obtenerTallaPorId(Integer idTalla) {
        return this.tallaRepository.findById(idTalla);
    }

    @Override
    public String actualizarTallaPorId(TallaModel talla, Integer idTalla) {

        String textoRespuesta = "";

        // Verificamos si existe para actualizar.
        try {
            Optional<TallaModel> tallEncontrada = this.tallaRepository.findById(idTalla);

            if (tallEncontrada.isPresent()) {

                TallaModel tallaActualizar = tallEncontrada.get();

                BeanUtils.copyProperties(talla, tallaActualizar);

                this.tallaRepository.save(tallaActualizar);

                return "La talla con código: " + idTalla + ", Ha sido actualizado con éxito.";

            } else {

                textoRespuesta = "La talla con código: " + idTalla + ", No existe en el sistema. Por ende el proceso no se realizo correctamente.";
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

