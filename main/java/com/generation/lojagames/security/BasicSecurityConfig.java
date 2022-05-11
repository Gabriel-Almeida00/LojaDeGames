package com.generation.lojagames.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
//Notação security
@EnableWebSecurity
public class BasicSecurityConfig extends WebSecurityConfigurerAdapter{
	//serve para comparar os dados salvos no banco de dados
		@Autowired
		private UserDetailsService userDetailsservice;
		
		 //usuario em memoria para teste
		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception{
			
			 auth.userDetailsService(userDetailsservice);

			auth.inMemoryAuthentication()
			.withUser("root")
			.password(passwordEncoder().encode("root"))
			.authorities("ROLE_USER");
				
		}	
		//notação que deixa uma função acessivel globalmente em toda aplicação
		@Bean
		
		//função que criptografa a senha digitada
		public PasswordEncoder passwordEncoder() {
			return new BCryptPasswordEncoder();
		}
		
		@Override
		protected  void configure(HttpSecurity http) throws Exception{
			http.authorizeRequests()
			.antMatchers("/usuarios/logar").permitAll()
			.antMatchers("/usuarios/cadastrar").permitAll()
			.antMatchers(HttpMethod.OPTIONS).permitAll()//http options para saber quais opcçoes de metodos acessiveis na api
			.anyRequest().authenticated()
			.and().httpBasic()
			.and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and().cors()//liberar acesso do backend 
			.and().csrf().disable();
		}
}
