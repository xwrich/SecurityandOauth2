package com.xxxx.springsecurityoauth2demo.controller;

import io.jsonwebtoken.Jwts;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;

/**
 * @Author: Dock
 * @CreateTime: 2022/1/12
 * @Description:
 */
@RestController
@RequestMapping("/user")
public class UserController {

    /**
     * 获取当前用户
     */

    @RequestMapping("/getCurrentUser")
    public Object getCurrentUser(Authentication authentication) {
        return authentication.getPrincipal();
    }

    /**
     * 获取当前用户
     */

    @RequestMapping("/getCurrentUserFromJwt")
    public Object getCurrentUserFromJwt(Authentication authentication, HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        String token = header.substring(header.indexOf("bearer") + 7);
        return Jwts.parser()
                .setSigningKey("test_key".getBytes(StandardCharsets.UTF_8))
                .parseClaimsJws(token)
                .getBody();
    }
}
