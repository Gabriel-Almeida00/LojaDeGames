package com.generation.lojagames.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.generation.lojagames.model.Usuario;

@Repository
public interface UsuarioRepository extends  JpaRepository<Usuario, Long>{
	// Quando não se sabe qual tipo de resposta pode ter ao buscar na requisição e tem mais de uma possível
		public Optional<Usuario> findByUsuario(String usuario);
}
