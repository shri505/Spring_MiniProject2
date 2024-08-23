package com.example.Spring_Login_Eg3.service;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Date;
import java.util.Map;
import java.util.function.Function;

public interface IJwtService
{

    String generateToken(String userName);

    String extractUsername(String token);

    Date extractExpiration(String token);

    <T> T extractClaim(String token, Function<io.jsonwebtoken.Claims, T> claimsResolver);

    boolean validateToken(String token, UserDetails userDetails);
}
