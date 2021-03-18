package com.pharma.credentials.controller;

import com.pharma.credentials.models.UserEmail;
import com.pharma.credentials.service.EmailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Random;

@RestController
@CrossOrigin()
public class HelloWorldController {
    @Autowired
    EmailService emailService;

    @RequestMapping(value = "/greeting", method = RequestMethod.GET)
    public String getEmployees() {
        return "Welcome!";
    }

    @RequestMapping(value = "/email", method = RequestMethod.POST)
    public ResponseEntity<?> sendEmail(@RequestBody UserEmail user) throws Exception {
        String twoFaCode = String.valueOf(new Random().nextInt(9999) + 1000);

        emailService.sendEmail(user.getEmail(), twoFaCode);

        return new ResponseEntity<>(HttpStatus.OK);
    }
}
