package org.ldv.AppStarter_ToDoList.controller

// Ajout des imports pour la journalisation :
import jakarta.servlet.http.HttpServletRequest
import org.ldv.AppStarter_ToDoList.service.AuditLogService

import org.ldv.AppStarter_ToDoList.entity.TaskStatus
import org.ldv.AppStarter_ToDoList.service.TaskService
import org.ldv.AppStarter_ToDoList.service.UserService
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.*
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

@Controller
@RequestMapping("/tasks")
class TaskController(
    private val taskService: TaskService,
    private val userService: UserService,
    // Ajout sur service de logs :
    private val auditLogService: AuditLogService
) {

    @GetMapping
    fun listTasks(authentication: Authentication, model: Model): String {
        val user = userService.findByUsername(authentication.name)!!
        val tasks = taskService.getUserTasks(user)
        model.addAttribute("tasks", tasks)
        model.addAttribute("username", user.username)
        return "tasks"
    }

    @PostMapping("/create")
    fun createTask(
        @RequestParam title: String,
        @RequestParam(required = false) description: String?,
        @RequestParam(required = false) dueDate: String?,
        authentication: Authentication,
        request: HttpServletRequest
    ): String {
        val user = userService.findByUsername(authentication.name)!!

        val parsedDueDate = dueDate?.takeIf { it.isNotBlank() }?.let {
            LocalDateTime.parse(it, DateTimeFormatter.ISO_LOCAL_DATE_TIME)
        }

        taskService.createTask(title, description, parsedDueDate, user)

        // Journalisation à implémenter par les étudiants ici plus tard
        // (appel à un futur AuditLogService)
        auditLogService.log(
            username = user.username,
            action = "CREATE_TASK",
            details = "Création de la tâche : $title",
            request = request
        )

        return "redirect:/tasks"
    }

    @PostMapping("/update/{id}")
    fun updateTask(
        @PathVariable id: Long,
        @RequestParam title: String,
        @RequestParam(required = false) description: String?,
        @RequestParam status: String,
        @RequestParam(required = false) dueDate: String?,
        authentication: Authentication,
        request: HttpServletRequest
    ): String {
        val task = taskService.getTaskById(id) ?: return "redirect:/tasks"

        if (task.user.username != authentication.name) {
            return "redirect:/tasks"
        }

        val parsedDueDate = dueDate?.takeIf { it.isNotBlank() }?.let {
            LocalDateTime.parse(it, DateTimeFormatter.ISO_LOCAL_DATE_TIME)
        }

        taskService.updateTask(
            task,
            title,
            description,
            TaskStatus.valueOf(status),
            parsedDueDate
        )

        // Journalisation à implémenter par les étudiants ici plus tard
        auditLogService.log(
            username = authentication.name,
            action = "UPDATE_TASK",
            details = "Modification tâche #$id (titre=$title, statut=$status)",
            request = request
        )

        return "redirect:/tasks"
    }

    @PostMapping("/delete/{id}")
    fun deleteTask(
        @PathVariable id: Long,
        authentication: Authentication,
        request: HttpServletRequest
    ): String {
        val task = taskService.getTaskById(id)

        if (task != null && task.user.username == authentication.name) {
            taskService.deleteTask(id)

            // Journalisation à implémenter par les étudiants ici plus tard
            auditLogService.log(
                username = authentication.name,
                action = "DELETE_TASK",
                details = "Suppression tâche #$id",
                request = request
            )
        }




        return "redirect:/tasks"
    }
}
