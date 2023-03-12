package com.system.RegisterationSystem.auth;
import com.system.RegisterationSystem.security.ApplicationRoles;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class ApplicationUserService implements UserDetailsService {

    private final ApplicationUserRepository applicationUserRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationUserService(ApplicationUserRepository applicationUserRepository, PasswordEncoder passwordEncoder) {
        this.applicationUserRepository = applicationUserRepository;
        this.passwordEncoder = passwordEncoder;
    }


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        List<ApplicationUser> applicationUsers=applicationUserRepository.findAll();
        for (int i=0;i<applicationUsers.size();i++){
            String role=applicationUsers.get(i).getRole();
            ApplicationRoles roleEnum=ApplicationRoles.fromString(role);
            Set<SimpleGrantedAuthority> permissions=roleEnum.getPermissions().stream()
                    .map(permission->new SimpleGrantedAuthority((permission.getPermission())))
                    .collect(Collectors.toSet());
            permissions.add(new SimpleGrantedAuthority("ROLE_"+role));
            applicationUsers.get(i).setGrantedAuthorities(permissions);
            permissions.clear();
        }
         return (applicationUsers.stream()
                 .filter(user -> user.getUsername().equals(username)).findFirst().orElseThrow(() ->
                         new UsernameNotFoundException(String.format("Username %s not found", username))
                 ));
    }
}
