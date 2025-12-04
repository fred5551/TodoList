package org.ldv.AppStarter_ToDoList.controller

// Ajout de l'import pour le service de log :
import org.ldv.AppStarter_ToDoList.service.AuditLogService

import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping

@Controller
@RequestMapping("/admin")
class AdminController(
    // Ajout de l'injection du service de log
    private val auditLogService: AuditLogService
) {

    @GetMapping
    fun adminPanel(model: Model): String {
        // Pour l’instant, aucun log n’est enregistré.
        // On passe une liste vide pour que la vue fonctionne sans erreur.

        // Ajout de la liste de logs renseignée par le service :
        val logs = auditLogService.getAllLogs()
        // On passe en argument logs à la place de la liste vide :
        model.addAttribute("logs", logs)

        // Les étudiants devront plus tard :
        //  - créer AuditLog/AuditLogRepository/AuditLogService
        //  - injecter AuditLogService ici
        //  - remplacer la liste vide par les vrais logs
        return "admin"
    }
}
