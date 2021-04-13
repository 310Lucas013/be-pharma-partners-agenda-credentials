package com.pharma.credentials.service;

import com.pharma.credentials.exeptions.UsernameExistsException;
import com.pharma.credentials.models.UserDao;
import com.pharma.credentials.models.UserDto;
import com.pharma.credentials.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.HashSet;
import java.util.Set;

@Service
public class JwtUserDetailsService implements UserDetailsService {
    @Autowired
    private UserRepository userRepo;

    @Autowired
    private PasswordEncoder bcryptEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDao user = userRepo.findByUsername(username);

        if (user == null) {
            throw new UsernameNotFoundException("User not found with username: " + username);
        }

        return new User(user.getUsername(), user.getPassword(), getAuthority(user));
    }

    private Set getAuthority(UserDao user) {
        Set authorities = new HashSet<>();
        user.getRoles().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getDescription()));
        });
        return authorities;
    }

    public List<UserDao> getAll() {
        return userRepo.findAll();
    }

    public UserDao save(UserDto user) throws UsernameExistsException {
        if (usernameExist(user.getUsername())) {
            throw new UsernameExistsException("There is an account with that email address: " + user.getUsername());
        }

        UserDao newUser = new UserDao();
        newUser.setUsername(user.getUsername());
        newUser.setPassword(bcryptEncoder.encode(user.getPassword()));
        newUser.setAuthenticated(false);
        newUser.setSecret(user.getSecret());

        if(user.isUsing2Fa()){
            newUser.setUsing2Fa(true);
        }else {
            newUser.setUsing2Fa(false);
        }

        return userRepo.save(newUser);
    }

    private boolean usernameExist(String username) {
        final UserDao user = userRepo.findByUsername(username);
        return user != null;
    }

    public UserDao update(UserDto user){
        var updatedUser = userRepo.findByUsername(user.getUsername());

        updatedUser.setAuthenticated(user.isAuthenticated());


        return userRepo.save(updatedUser);
    }

    public UserDto findUserByUsername(String user){
        UserDao userDao = userRepo.findByUsername(user);

        if (userDao == null) {
            throw new UsernameNotFoundException("User not found with username: " + user);
        }

        UserDto newUser = new UserDto();
        newUser.setUsername(user);
        newUser.setAuthenticated(userDao.isAuthenticated());
        newUser.setSecret(userDao.getSecret());
        newUser.setUsing2Fa(userDao.isUsing2Fa());

        return newUser;
    }
}

