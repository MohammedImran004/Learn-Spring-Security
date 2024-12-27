package com.imran.Learn_Spring_Security.resource;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloWorldController {
    @GetMapping("/hello-world")
    public String hello() {
        return "Hello World";
    }
    
}
