package com.numarics.user.service;

import com.numarics.user.model.User;

public interface UserService {

    User save(User user);

    User findByUsername(String username);

}
