package com.system.RegisterationSystem.security;
import com.system.RegisterationSystem.auth.ApplicationUserService;
import com.system.RegisterationSystem.jwt.JwtConfig;
import com.system.RegisterationSystem.jwt.JwtSecretKey;
import com.system.RegisterationSystem.jwt.JwtTokenVerifier;
import com.system.RegisterationSystem.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import static com.system.RegisterationSystem.security.ApplicationPermissions.COURSE_WRITE;
import static com.system.RegisterationSystem.security.ApplicationRoles.*;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class ApplicationSecurityConfig {
    private static final String[] AUTH_WHITELIST = {
            "/","index","/css/*","/js/*"
    };
    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;
    private final JwtConfig jwtConfig;
    private final JwtSecretKey secretKey;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder,
                                     ApplicationUserService applicationUserService, JwtConfig jwtConfig, JwtSecretKey secretKey) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{

        http
//                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                .and()
                .csrf().disable()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(
                        http.getSharedObject(AuthenticationConfiguration.class)), jwtConfig, secretKey))
                .addFilterAfter(new JwtTokenVerifier(secretKey.secretKey(),jwtConfig),JwtUsernameAndPasswordAuthenticationFilter.class)
                .authorizeHttpRequests((auth) -> auth

                        .requestMatchers(AUTH_WHITELIST).permitAll()
                        .requestMatchers("/api/**").hasRole(USER.name())
                        .requestMatchers(HttpMethod.GET,"/info").hasAuthority(COURSE_WRITE.getPermission())
                        .requestMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                        .requestMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                        .requestMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                        .requestMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(TRAINEE_ADMIN.name(),ADMIN.name())
                        .anyRequest().authenticated()

                )
                .authenticationProvider(daoAuthenticationProvider());
               // .httpBasic(withDefaults())


        //Form Based AUTHENTICATION CONFIG

//                .formLogin()
//                    .loginPage("/login").permitAll()
////                    .defaultSuccessUrl("/courses",true)
//                    .passwordParameter("password")
//                    .usernameParameter("username")
//                .and()
//                .rememberMe()
//                    .tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(21))//2 weeks for session
//                    .key("asdfasfas")
//                    .rememberMeParameter("remember-me")
//                .and()
//                    .logout()
//                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout","GET"))
//                    .logoutUrl("/logout")
//                    .clearAuthentication(true)
//                    .invalidateHttpSession(true)
//                    .deleteCookies("JSESSIONID","remember-me")
//                    .logoutSuccessUrl("/login");
        return http.build();

    }
//    @Bean
//    public UserDetailsService users( ) {
//        UserDetails user = User.builder()
//                .username("user")
//                .password(passwordEncoder.encode("password"))
//                .authorities(USER.getGrantedAuthorities())
////                .roles(USER.name())//ROLE_USER
//                .build();
//        UserDetails admin = User.builder()
//                .username("admin")
//                .password(passwordEncoder.encode("admin"))
//                .authorities(ADMIN.getGrantedAuthorities())
////                .roles(ADMIN.name())//ROLE_ADMIN
//                .build();
//        UserDetails traineeAdmin = User.builder()
//                .username("trainee")
//                .password(passwordEncoder.encode("123"))
//                .authorities(TRAINEE_ADMIN.getGrantedAuthorities())
////                .roles(TRAINEE_ADMIN.name())//ROLE_TRAINEE_ADMIN
//                .build();
//
//        return  new InMemoryUserDetailsManager(user,admin,traineeAdmin);
//    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider=new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }


}
