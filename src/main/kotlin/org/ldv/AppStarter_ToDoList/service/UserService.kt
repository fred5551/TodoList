package org.ldv.AppStarter_ToDoList.service

import org.ldv.AppStarter_ToDoList.entity.User
import org.ldv.AppStarter_ToDoList.repository.UserRepository
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service

@Service
class UserService(
    private val userRepository: UserRepository
) : UserDetailsService {

    private lateinit var passwordEncoder: PasswordEncoder

    // Injection via setter pour éviter la dépendance circulaire
    fun setPasswordEncoder(encoder: PasswordEncoder) {
        this.passwordEncoder = encoder
    }

    override fun loadUserByUsername(username: String): UserDetails {
        val user = userRepository.findByUsername(username)
            ?: throw UsernameNotFoundException("Utilisateur non trouvé: $username")

        return org.springframework.security.core.userdetails.User(
            user.username,
            user.password,
            user.enabled,
            true, true, true,
            listOf(SimpleGrantedAuthority("ROLE_${user.role}"))
        )
    }

    fun createUser(username: String, password: String, email: String): User {
        val user = User(
            username = username,
            password = passwordEncoder.encode(password),
            email = email,
            role = "USER"
        )
        return userRepository.save(user)
    }

    fun findByUsername(username: String): User? {
        return userRepository.findByUsername(username)
    }

    fun existsByUsername(username: String): Boolean {
        return userRepository.existsByUsername(username)
    }
}