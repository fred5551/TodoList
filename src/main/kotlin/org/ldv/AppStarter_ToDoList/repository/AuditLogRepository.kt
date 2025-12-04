package org.ldv.AppStarter_ToDoList.repository

import org.ldv.AppStarter_ToDoList.entity.AuditLog
import org.springframework.data.jpa.repository.JpaRepository

interface AuditLogRepository : JpaRepository<AuditLog, Long> {
    fun findAllByOrderByTimestampDesc(): List<AuditLog>
    fun findByUsernameOrderByTimestampDesc(username: String): List<AuditLog>
}