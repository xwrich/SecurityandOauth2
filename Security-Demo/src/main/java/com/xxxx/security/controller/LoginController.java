package com.xxxx.security.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * @Author: Dock
 * @CreateTime: 2022/1/3
 * @Description: 登录控制器
 */

@Controller
public class LoginController {

    /**
     * 登录
     * @return
     */
//    @RequestMapping("login")
//    public String Login(){
//        System.out.println("执行登录方法！");
//        return "redirect:index.html";
//    }

    /**
     * 页面跳转
     * @return
     */
    //@Secured("ROLE_abc")
    //PreAuthorize的表达式允许ROLE_开头，也可以不以ROLE_开头，配置类不允许以ROLE_开头
    @PreAuthorize("hasRole('abc')")
    @RequestMapping("toMain")
    public String toMain(){
        return "redirect:main.html";
    }

    @RequestMapping("toError")
    public String toError(){
        return "redirect:error.html";
    }

    @RequestMapping("demo")
    public String Demo(){
        return "demo";
    }

    /**
     * 页面跳转
     * @return
     */
    @RequestMapping("showLogin")
    public String showLogin() {
        return "login";
    }

}
