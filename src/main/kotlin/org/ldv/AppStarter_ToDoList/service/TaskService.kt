package org.ldv.AppStarter_ToDoList.service

import org.ldv.AppStarter_ToDoList.entity.Task
import org.ldv.AppStarter_ToDoList.entity.TaskStatus
import org.ldv.AppStarter_ToDoList.entity.User
import org.ldv.AppStarter_ToDoList.repository.TaskRepository
import org.springframework.stereotype.Service
import java.time.LocalDateTime

@Service
class TaskService(
    private val taskRepository: TaskRepository
) {

    fun createTask(title: String, description: String?, dueDate: LocalDateTime?,
                   user: User
    ): Task {
        val task = Task(
            title = title,
            description = description,
            dueDate = dueDate,
            user = user
        )
        return taskRepository.save(task)
    }

    fun getUserTasks(user: User): List<Task> {
        return taskRepository.findByUserOrderByCreatedAtDesc(user)
    }

    fun getTaskById(id: Long): Task? {
        return taskRepository.findById(id).orElse(null)
    }
    fun updateTask(task: Task, title: String, description: String?, status:
    TaskStatus, dueDate: LocalDateTime?): Task {
        task.title = title
        task.description = description
        task.status = status
        task.dueDate = dueDate
        task.updatedAt = LocalDateTime.now()
        return taskRepository.save(task)
    }

    fun deleteTask(id: Long) {
        taskRepository.deleteById(id)
    }
}