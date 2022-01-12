package com.xxxx.security.service;

import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;

/**
 * @Author: Dock
 * @CreateTime: 2022/1/11
 * @Description:
 */
public interface MyService {
    boolean hasPermission(HttpServletRequest request, Authentication authentication);
}
