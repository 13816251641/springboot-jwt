package com.lujieni.jwt.dao;

import com.lujieni.jwt.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User,Integer> {
     User findByUsername(String username);
}
