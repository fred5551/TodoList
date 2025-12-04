package org.ldv.AppStarter_ToDoList.config

// Ajout de l'import du service AuditLogService :
import org.ldv.AppStarter_ToDoList.service.AuditLogService

// Ajout du gestionnaire d'authentification de Spring Security :
import org.springframework.security.web.authentication.AuthenticationSuccessHandler

// Ajout du gestionnaire de déconnexion de Spring Security :
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler

// AJOUT TP2 - Import du logger SLF4J
import org.slf4j.LoggerFactory

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

    // AJOUT TP2 - Logger dédié à l'audit (redirigé vers audit.log via logback-spring.xml)
    private val auditLogger = LoggerFactory.getLogger("AUDIT")

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
            val ip = request.remoteAddr
            auditLogService.log(
                username = username,
                action = "LOGIN",
                details = "Connexion réussie",
                request = request
            )

            // AJOUT TP2 - écriture dans audit.log
            auditLogger.info("LOGIN user={} ip={}", username, ip)
            response.sendRedirect("/tasks")
        }

    // Ajout du gestionnaire de déconnexion :
    private fun customLogoutSuccessHandler(): LogoutSuccessHandler =
        LogoutSuccessHandler { request, response, authentication ->
            val username = authentication?.name ?: "anonymous"
            val ip = request.remoteAddr

            // (audit en base - TP1)
            auditLogService.log(
                username = username,
                action = "LOGOUT",
                details = "Déconnexion",
                request = request
            )

            // AJOUT TP2 - écriture dans audit.log
            auditLogger.info("LOGOUT user={} ip={}", username, ip)

            response.sendRedirect("/login?logout")
        }

}
