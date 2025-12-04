package org.ldv.AppStarter_ToDoList

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class AppStarterToDoListApplication

fun main(args: Array<String>) {
	runApplication<AppStarterToDoListApplication>(*args)
}
