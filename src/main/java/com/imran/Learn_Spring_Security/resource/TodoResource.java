package com.imran.Learn_Spring_Security.resource;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TodoResource {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    // Mutable list to allow modifications
    private static final List<Todo> Todos = new ArrayList<>(List.of(
            new Todo("imran", "Learn Spring Security"),
            new Todo("imran", "Learn Spring Boot"),
            new Todo("imran", "Learn Full Stack")
    ));

    @GetMapping("/todo")
    public List<Todo> retrieveAllTodos() {
        logger.info("Retrieving all todos");
        return Todos;
    }

    @GetMapping("/users/{username}/todo")
    public Todo retrieveTodosForUser(@PathVariable String username) {
        logger.info("Retrieving todos for user: {}", username);
        return Todos.stream()
                .filter(todo -> todo.Username().equals(username))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("Todo not found for user: " + username));
    }

    @PostMapping("/users/{username}/todo")
    public void createTodosForUser(@PathVariable String username, @RequestBody Todo todo) {
        logger.info("Creating todo for user: {}", username);
        // Todos.add(new Todo(username, todo.Description()));
    }
}

// Record to represent a Todo
record Todo(String Username, String Description) {}
