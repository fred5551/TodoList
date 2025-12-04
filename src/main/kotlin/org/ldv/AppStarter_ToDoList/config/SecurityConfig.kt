package org.ldv.AppStarter_ToDoList.config

// Ajout de l'import du service AuditLogService :
import org.ldv.AppStarter_ToDoList.service.AuditLogService

// Ajout du gestionnaire d'authentification de Spring Security :
import org.springframework.security.web.authentication.AuthenticationSuccessHandler

// Ajout du gestionnaire de déconnexion de Spring Security :
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.web.SecurityFilterChain


@Configuration
@EnableWebSecurity
class SecurityConfig(
    // Injection du service AuditLogService par le constructeur :
    private val auditLogService: AuditLogService
) {

    @Bean
    fun passwordEncoder(): PasswordEncoder = BCryptPasswordEncoder()

    @Bean
    fun authenticationManager(config: AuthenticationConfiguration): AuthenticationManager =
        config.authenticationManager

    @Bean
    fun authenticationProvider(
        userDetailsService: UserDetailsService,
        passwordEncoder: PasswordEncoder
    ): DaoAuthenticationProvider {
        val authProvider = DaoAuthenticationProvider()
        authProvider.setUserDetailsService(userDetailsService)
        authProvider.setPasswordEncoder(passwordEncoder)
        return authProvider
    }

    @Bean
    fun filterChain(
        http: HttpSecurity
    ): SecurityFilterChain {
        http
            .authorizeHttpRequests { auth ->
                auth
                    .requestMatchers("/register", "/css/**", "/h2-console/**").permitAll()
                    .requestMatchers("/admin/**").hasRole("ADMIN")
                    .anyRequest().authenticated()
            }
            .formLogin { form ->
                form
                    .loginPage("/login")
                    //.defaultSuccessUrl("/tasks", true)  // Redirection standard
                    // Remplacement par le gestionnaire personnalisé
                    .successHandler(customAuthenticationSuccessHandler())
                    .permitAll()
            }
            .logout { logout ->
                logout
                    //.logoutSuccessUrl("/login?logout")
                    // Remplacement par le gestionnaire personnalisé
                    .logoutSuccessHandler(customLogoutSuccessHandler())
                    .permitAll()
            }
            .csrf { csrf ->
                csrf.ignoringRequestMatchers("/h2-console/**")
            }
            .headers { headers ->
                headers.frameOptions { it.disable() }
            }

        return http.build()
    }

    // Ajout du gestionnaire de succès d'authentification :
    private fun customAuthenticationSuccessHandler(): AuthenticationSuccessHandler =
        AuthenticationSuccessHandler { request, response, authentication ->
            val username = authentication.name
            auditLogService.log(
                username = username,
                action = "LOGIN",
                details = "Connexion réussie",
                request = request
            )
            response.sendRedirect("/tasks")
        }

    // Ajout du gestionnaire de déconnexion :
    private fun customLogoutSuccessHandler(): LogoutSuccessHandler =
        LogoutSuccessHandler { request, response, authentication ->
            val username = authentication?.name ?: "anonymous"
            auditLogService.log(
                username = username,
                action = "LOGOUT",
                details = "Déconnexion",
                request = request
            )
            response.sendRedirect("/login?logout")
        }

}
