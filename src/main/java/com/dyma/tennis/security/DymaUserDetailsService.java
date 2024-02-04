package com.dyma.tennis.security;

import com.dyma.tennis.data.RoleEntity;
import com.dyma.tennis.data.UserEntity;
import com.dyma.tennis.data.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class DymaUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String login) throws UsernameNotFoundException {
        return userRepository.findOneWithRolesByLoginIgnoreCase(login)
                .map(userEntity -> createSpringSecurityUser(login, userEntity))
                .orElseThrow(() -> new UsernameNotFoundException("User with login " + login + " could not be found."));
    }

    private org.springframework.security.core.userdetails.User createSpringSecurityUser(String login, UserEntity user) {
        List<SimpleGrantedAuthority> grantedRoles = user
                .getRoles()
                .stream()
                .map(RoleEntity::getName)
                .map(SimpleGrantedAuthority::new)
                .toList();
        return new org.springframework.security.core.userdetails.User(user.getLogin(), user.getPassword(), grantedRoles);
    }
}
