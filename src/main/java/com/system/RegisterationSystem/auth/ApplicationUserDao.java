package com.system.RegisterationSystem.auth;

import com.system.RegisterationSystem.auth.ApplicationUser;

import java.util.Optional;

public interface ApplicationUserDao {

    Optional<ApplicationUser> selectApplicationUserByUsername(String username);

}