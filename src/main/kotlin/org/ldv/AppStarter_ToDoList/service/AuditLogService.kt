package org.ldv.AppStarter_ToDoList.service

import jakarta.servlet.http.HttpServletRequest
import org.ldv.AppStarter_ToDoList.entity.AuditLog
import org.ldv.AppStarter_ToDoList.repository.AuditLogRepository
import org.springframework.stereotype.Service

@Service
class AuditLogService(
    private val auditLogRepository: AuditLogRepository
) {
    fun log(username: String, action: String, details: String?, request:
    HttpServletRequest) {
        val ip = request.remoteAddr
        val logEntry = AuditLog(
            username = username,
            action = action,
            details = details,
            ipAddress = ip
        )
        auditLogRepository.save(logEntry)
    }
    fun getAllLogs(): List<AuditLog> =
        auditLogRepository.findAllByOrderByTimestampDesc()
    fun getUserLogs(username: String): List<AuditLog> =
        auditLogRepository.findByUsernameOrderByTimestampDesc(username)
}