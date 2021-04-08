package com.pharma.credentials.service;

import com.pharma.credentials.exeptions.UsernameExistsException;
import com.pharma.credentials.models.UserDao;
import com.pharma.credentials.models.UserDto;
import com.pharma.credentials.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

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
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(),
                new ArrayList<>());
    }

    public UserDao save(UserDto user) throws UsernameExistsException {
        if (usernameExist(user.getUsername())) {
            throw new UsernameExistsException("There is an account with that email address: " + user.getUsername());
        }

        UserDao newUser = new UserDao();
        newUser.setUsername(user.getUsername());
        newUser.setPassword(bcryptEncoder.encode(user.getPassword()));
        return userRepo.save(newUser);
    }

    private boolean usernameExist(String username) {
        final UserDao user = userRepo.findByUsername(username);
        return user != null;
    }

    public List<UserDao> getAll() {
        return userRepo.findAll();
    }
}
