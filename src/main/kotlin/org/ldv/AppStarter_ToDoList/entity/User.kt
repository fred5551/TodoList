package org.ldv.AppStarter_ToDoList.entity

import jakarta.persistence.*
import java.time.LocalDateTime


@Entity
@Table(name = "users")
data class User(
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    val id: Long? = null,

    @Column(unique = true, nullable = false)
    var username: String,

    @Column(nullable = false)
    var password: String,

    @Column(nullable = false)
    var email: String,

    @Column(nullable = false)
    var role: String = "USER", // USER ou ADMIN

    @Column(nullable = false)
    var enabled: Boolean = true,

    @Column(nullable = false)
    val createdAt: LocalDateTime = LocalDateTime.now(),

    @OneToMany(mappedBy = "user", cascade = [CascadeType.ALL], orphanRemoval =
        true)
    val tasks: MutableList<Task> = mutableListOf()
)