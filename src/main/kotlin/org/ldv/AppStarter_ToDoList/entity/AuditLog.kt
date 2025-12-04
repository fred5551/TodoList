package org.ldv.AppStarter_ToDoList.entity

import jakarta.persistence.*
import java.time.LocalDateTime

@Entity
data class AuditLog(
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    val id: Long = 0,
    @Column(nullable = false)
    val username: String,
    @Column(nullable = false)
    val action: String,
    @Column(nullable = true)
    val details: String? = null,
    @Column(nullable = false)
    val ipAddress: String,
    @Column(nullable = false)
    val timestamp: LocalDateTime = LocalDateTime.now()
)