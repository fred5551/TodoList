package org.ldv.AppStarter_ToDoList.config

import org.ldv.AppStarter_ToDoList.entity.User
import org.ldv.AppStarter_ToDoList.repository.UserRepository
import org.ldv.AppStarter_ToDoList.service.UserService
import org.springframework.boot.CommandLineRunner
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.crypto.password.PasswordEncoder

@Configuration
class DataInitializer {

    @Bean
    fun initData(
        userRepository: UserRepository,
        passwordEncoder: PasswordEncoder,
        userService: UserService
    ) = CommandLineRunner {
        // Injecter le passwordEncoder dans le UserService
        userService.setPasswordEncoder(passwordEncoder)

        // Créer un admin par défaut
        if (!userRepository.existsByUsername("admin")) {
            val admin = User(
                username = "admin",
                password = passwordEncoder.encode("admin123"),
                email = "admin@todolist.com",
                role = "ADMIN"
            )
            userRepository.save(admin)
        }

        // Créer un utilisateur de test
        if (!userRepository.existsByUsername("user")) {
            val user = User(
                username = "user",
                password = passwordEncoder.encode("user123"),
                email = "user@todolist.com",
                role = "USER"
            )
            userRepository.save(user)
        }
    }
}