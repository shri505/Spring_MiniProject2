package com.example.Spring_Login_Eg3.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.example.Spring_Login_Eg3.entity.UserInfo;
import java.util.Optional;

@Repository
public interface UserInfoRepository extends JpaRepository<UserInfo, Integer>

{
    Optional<UserInfo> findByUsername(String username);

}