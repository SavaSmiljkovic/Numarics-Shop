package com.numarics.user.service.impl;

import com.numarics.user.model.User;
import com.numarics.user.repository.UserRepository;
import com.numarics.user.service.UserService;
import org.springframework.stereotype.Service;

@Service
public class DefaultUserService implements UserService {

    private final UserRepository userRepository;

    public DefaultUserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public User save(User user) {
        return userRepository.save(user);
    }

    @Override
    public User findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

}
