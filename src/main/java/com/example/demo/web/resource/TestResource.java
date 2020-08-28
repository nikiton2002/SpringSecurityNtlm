package com.example.demo.web.resource;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestResource {

    @RequestMapping("/test")
    public String test() {
        return "test";
    }

}
