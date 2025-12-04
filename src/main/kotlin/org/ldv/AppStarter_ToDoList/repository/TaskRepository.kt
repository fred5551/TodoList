package org.ldv.AppStarter_ToDoList.repository

import org.ldv.AppStarter_ToDoList.entity.Task
import org.ldv.AppStarter_ToDoList.entity.User
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.stereotype.Repository


@Repository
interface TaskRepository : JpaRepository<Task, Long> {
    fun findByUserOrderByCreatedAtDesc(user: User): List<Task>
}