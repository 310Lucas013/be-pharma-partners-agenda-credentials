package com.pharma.credentials.controller;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@CrossOrigin()
public class HelloWorldController {
    @RequestMapping(value = "/greeting", method = RequestMethod.GET)
    public String getEmployees(Principal user) {
        System.out.println("principal: " +user.getName());
        return "Welcome!";
    }
}
