package org.ldv.AppStarter_ToDoList.controller

import org.ldv.AppStarter_ToDoList.service.UserService
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam

@Controller
class AuthController(
    private val userService: UserService
) {

    @GetMapping("/login")
    fun login(): String = "login"

    @GetMapping("/register")
    fun registerForm(): String = "register"

    @PostMapping("/register")
    fun register(
        @RequestParam username: String,
        @RequestParam password: String,
        @RequestParam email: String,
        model: Model
    ): String {
        if (userService.existsByUsername(username)) {
            model.addAttribute("error", "Ce nom d'utilisateur existe déjà")
            return "register"
        }

        userService.createUser(username, password, email)
        return "redirect:/login?registered"
    }
}