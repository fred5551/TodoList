package org.ldv.AppStarter_ToDoList.entity

import jakarta.persistence.*
import java.time.LocalDateTime


@Entity
@Table(name = "tasks")
data class Task(
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    val id: Long? = null,

    @Column(nullable = false)
    var title: String,

    @Column(length = 1000)
    var description: String? = null,

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    var status: TaskStatus = TaskStatus.TODO,

    @Column(nullable = false)
    val createdAt: LocalDateTime = LocalDateTime.now(),

    var updatedAt: LocalDateTime = LocalDateTime.now(),

    var dueDate: LocalDateTime? = null,

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    var user: User
)

enum class TaskStatus {
    TODO, IN_PROGRESS, DONE
}