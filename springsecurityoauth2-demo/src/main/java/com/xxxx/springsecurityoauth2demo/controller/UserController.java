package com.xxxx.springsecurityoauth2demo.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @Author: Dock
 * @CreateTime: 2022/1/12
 * @Description:
 */
@RestController
@RequestMapping("/user")
public class UserController {

    //获取当前用户
    @RequestMapping("/getCurrentUser")
    public Object getCurrentUser(Authentication authentication) {
        return authentication.getPrincipal();
    }
}
