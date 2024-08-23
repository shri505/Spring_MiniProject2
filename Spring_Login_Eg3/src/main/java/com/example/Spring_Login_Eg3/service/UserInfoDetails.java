package com.example.Spring_Login_Eg3.service;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import com.example.Spring_Login_Eg3.entity.UserInfo;
import java.util.Collection;

public class UserInfoDetails implements UserDetails
{

    private String username;
    private String password;

    public UserInfoDetails(UserInfo userInfo)
    {
        this.username = userInfo.getUsername();
        this.password = userInfo.getPassword();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}