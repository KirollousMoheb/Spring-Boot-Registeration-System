package com.system.RegisterationSystem.auth;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/info")
public class ApplicationUsersController {


    private final ApplicationUserRepository applicationUserRepository;

    public ApplicationUsersController(ApplicationUserRepository applicationUserRepository) {
        this.applicationUserRepository = applicationUserRepository;
    }

    @GetMapping
    public List<ApplicationUser> getUsers(){
        return applicationUserRepository.findAll();
    }



}
