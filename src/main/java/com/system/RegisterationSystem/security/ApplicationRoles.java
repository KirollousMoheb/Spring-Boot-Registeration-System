package com.system.RegisterationSystem.security;
import com.google.common.collect.Sets;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.util.Set;
import java.util.stream.Collectors;


public enum ApplicationRoles {
    USER(Sets.newHashSet()),ADMIN(Sets.newHashSet(
            ApplicationPermissions.COURSE_WRITE,
            ApplicationPermissions.COURSE_READ,
            ApplicationPermissions.STUDENT_READ,
            ApplicationPermissions.STUDENT_WRITE
)),TRAINEE_ADMIN(Sets.newHashSet(ApplicationPermissions.COURSE_READ,
            ApplicationPermissions.STUDENT_READ));

    private final Set<ApplicationPermissions>permissions;

    ApplicationRoles(Set<ApplicationPermissions> permissions) {
        this.permissions = permissions;
    }

    public Set<ApplicationPermissions> getPermissions() {
        return permissions;
    }
    public Set<SimpleGrantedAuthority> getGrantedAuthorities(){
        Set<SimpleGrantedAuthority> permissions= getPermissions().stream()
                .map(permission->new SimpleGrantedAuthority((permission.getPermission())))
                .collect(Collectors.toSet());
        permissions.add(new SimpleGrantedAuthority("ROLE_"+this.name()));
        return permissions;

    }
}
