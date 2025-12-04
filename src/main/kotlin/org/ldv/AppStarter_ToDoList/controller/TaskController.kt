package org.ldv.AppStarter_ToDoList.controller

// AJOUT TP2 - import du logger SLF4J pour les logs techniques
import org.slf4j.LoggerFactory

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
import org.springframework.data.jpa.domain.AbstractPersistable_.id

@Controller
@RequestMapping("/tasks")
class TaskController(
    private val taskService: TaskService,
    private val userService: UserService,
    private val auditLogService: AuditLogService
) {
    // AJOUT TP2 - Logger technique
    private val logger = LoggerFactory.getLogger(TaskController::class.java)
    // AJOUT TP2 - Logger d’audit dédié (redirigé vers audit.log)
    private val auditLogger = LoggerFactory.getLogger("AUDIT")

    @GetMapping
    fun listTasks(authentication: Authentication, model: Model): String {
        val user = userService.findByUsername(authentication.name)!!
        val tasks = taskService.getUserTasks(user)
// AJOUT TP2 - log technique lors de l’affichage de la liste des tâches
        logger.info("Affichage de la liste des tâches pour l'utilisateur {}",
            user.username)
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
// TP1 - journalisation en base
        auditLogService.log(
            username = user.username,
            action = "CREATE_TASK",
            details = "Création de la tâche : $title",
            request = request
        )
// AJOUT TP2 - journalisation fichier : audit.log
        auditLogger.info(
            "CREATE_TASK user={} title=\"{}\" dueDate={}",
            user.username,
            title,
            parsedDueDate
        )
// AJOUT TP2 - log technique classique
        logger.info(
            "Création d'une tâche pour {} : {}",
            user.username,
            title
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
// AJOUT TP2 - log technique si un utilisateur tente de modifier une tâche qui ne lui appartient pas
            logger.warn(
                "Tentative de mise à jour non autorisée de la tâche {} par l'utilisateur {}",
                id,
                authentication.name
            )
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
// TP1 - audit en base
        auditLogService.log(
            username = authentication.name,
            action = "UPDATE_TASK",
            details = "Modification tâche #$id (titre=$title, statut=$status)",
            request = request
        )
// AJOUT TP2 - audit fichier
        auditLogger.info(
            "UPDATE_TASK user={} taskId={} title=\"{}\" status={} dueDate={}",
            authentication.name,
            id,
            title,
            status,
            parsedDueDate
        )
// AJOUT TP2 - log technique lors de la mise à jour d’une tâche
        logger.info(
            "Mise à jour de la tâche {} par l'utilisateur {} : titre=\"{}\", statut={}, échéance={}",
            id,
            authentication.name,
            title,
            status,
            parsedDueDate
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
// AJOUT TP2 - audit fichier
            auditLogger.info(
                "DELETE_TASK user={} taskId={}",
                authentication.name,
                id
            )
// AJOUT TP2 - log technique lors de la suppression d’une tâche
            logger.info(
                "Suppression de la tâche {} par l'utilisateur {}",
                id,
                authentication.name
            )
        } else {
// AJOUT TP2 - log technique en cas de tentative de suppression non autorisée
            logger.warn(
                "Tentative de suppression non autorisée de la tâche {} par l'utilisateur {}",
                id,
                authentication.name
            )
// AJOUT TP2 - audit d'une tentative de suppression non autorisée
            auditLogger.warn(
                "FORBID_DELETE_TASK user={} taskId={}",
                id,
                authentication.name
            )
        }
        return "redirect:/tasks"
    }
}
