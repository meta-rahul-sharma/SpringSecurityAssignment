package com.security.springsecuritybasic.securingweb;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter implements WebMvcConfigurer {

		/**
		 * @author rahul sharma
		 *
		 * @param registry
		 */
		public void addViewControllers(ViewControllerRegistry registry) {
				registry.addViewController("/home").setViewName("home");
				registry.addViewController("/").setViewName("home");
				registry.addViewController("/hello").setViewName("hello");
				registry.addViewController("/login").setViewName("login");
		}

		/**
		 * @author rahul sharma
		 * method defines which URL paths should be secured and which should not
		 *
		 * @param http
		 * @throws Exception
		 */
		@Override
		protected void configure(HttpSecurity http) throws Exception {
				http
				.authorizeRequests()
				.antMatchers("/", "/home").permitAll()
				.anyRequest().authenticated()
				.and()
				.formLogin()
				.loginPage("/login")
				.defaultSuccessUrl("/hello")
				.permitAll()
				.and()
				.logout()
				.permitAll();
		}

//		/**
//		 * @author rahul sharma
//		 * to set up an in-memory single user
//		 * @return
//		 */
//		@Bean
//		@Override
//		public UserDetailsService userDetailsService() {
//				UserDetails user =
//								User.withDefaultPasswordEncoder()
//												.username("user")
//												.password("password")
//												.roles("USER")
//												.build();
//
//				return new InMemoryUserDetailsManager(user);
//		}


		/**
		 * @autho rahul sharma
		 * To set up in memory authentication of user with password encoder
		 * @param auth
		 * @throws Exception
		 */
		@Override
		public void configure(AuthenticationManagerBuilder auth) throws Exception{
				auth.inMemoryAuthentication()
								.passwordEncoder(passwordEncoder())
								.withUser("user")
								.password(passwordEncoder().encode("secret123"))
								.roles("USER");
		}

		@Bean
		public PasswordEncoder passwordEncoder() {
				return new BCryptPasswordEncoder();
		}
}