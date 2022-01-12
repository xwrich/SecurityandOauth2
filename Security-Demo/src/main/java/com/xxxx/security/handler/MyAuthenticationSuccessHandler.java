package com.xxxx.security.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @Author: Dock
 * @CreateTime: 2022/1/9
 * @Description:
 */
public class MyAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    public MyAuthenticationSuccessHandler(String url) {
        this.url = url;
    }

    private String url;


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        System.out.println(request.getRemoteAddr());

        User user = (User) authentication.getPrincipal();
        System.out.println(user.getUsername());
        //输出为null
        System.out.println(user.getPassword());
        System.out.println(user.getAuthorities());
        response.sendRedirect(url);
    }
}
