package com.system.RegisterationSystem.auth;


import org.springframework.security.access.prepost.PreAuthorize;
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
    //@PreAuthorize("hasAuthority('student:write')")
    public List<ApplicationUser> getUsers(){
        List<ApplicationUser>users=applicationUserRepository.findAll();
        return users;
    }



}
