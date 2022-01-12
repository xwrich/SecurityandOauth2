package com.xxxx.security.config;

import com.xxxx.security.handler.MyAccessDeniedHandler;
import com.xxxx.security.handler.MyAuthenticationFailureHandler;
import com.xxxx.security.handler.MyAuthenticationSuccessHandler;
import com.xxxx.security.service.UserDetailsServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;

/**
 * @Author: Dock
 * @CreateTime: 2022/1/4
 * @Description: SpringSecurity配置类
 */
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyAccessDeniedHandler accessDeniedHandler;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    @Autowired
    private DataSource dataSource;

    @Autowired
    private PersistentTokenRepository persistentTokenRepository;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //表单提交
        http.formLogin()
                .usernameParameter("username")
                .passwordParameter("password")
                //当发现时/login时认为登录，必须和表单提交的地址一样，去执行UserDetailsServiceImpl
                .loginProcessingUrl("/login")
                //自定义登录页面
//                .loginPage("/login.html")
                .loginPage("/showLogin")
                //登录成功后跳转页面，POST请求
                .successForwardUrl("/toMain")
                //登录成功处理器，不能和successForwardUrl共存
//                .successHandler(new MyAuthenticationSuccessHandler("http://www.baidu.com"))
//                .successHandler(new MyAuthenticationSuccessHandler("/main.html"))

                //登录失败后跳转页面，POST请求
                .failureForwardUrl("/toError");
                //登录失败处理器，failureForwardUrl共存
//                .failureHandler(new MyAuthenticationFailureHandler("/error.html"));

        //授权认证
        http.authorizeRequests()
                //error.html不需要被认证，以下两种效果相同
                .antMatchers("/error.html").permitAll()
//                .antMatchers("/error.html").access("permitAll()")
                //login.html不需要被认证
                .antMatchers("/showLogin").permitAll()
//                .antMatchers("/login.html").permitAll()
                .antMatchers("/js/**","/css/**","/images/**").permitAll()
//                .antMatchers("/**/*.png").permitAll()
                //正则表达式匹配
//                .regexMatchers(".+[.]png").permitAll()
//                .regexMatchers(HttpMethod.GET,"/demo").permitAll()
//                .mvcMatchers("/demo").servletPath("/xxxx").permitAll()
//                .antMatchers("/xxxx/demo").permitAll()
//                .antMatchers("/main1.html").hasAuthority("admin")

                //以下两种效果相同
//                .antMatchers("/main1.html").access("hashCode('abc')")
//                .antMatchers("/main1.html").hasRole("abc")
                //严格区分大小写
//                .antMatchers("/main1.html").hasAnyAuthority("admin","admiN")
                //IP地址判断
//                .antMatchers("/main1.html").hasIpAddress("127.0.0.1")

                //所有请求都必须被认证，必须登录之后被访问
                .anyRequest().authenticated();
//                .anyRequest().access("@myServiceImpl.hasPermission(request,authentication)");

        //关闭csrf防护
//        http.csrf().disable();

        //异常处理
//        http.exceptionHandling()
//                .accessDeniedHandler(accessDeniedHandler);

        //记住我
        http.rememberMe()
                //设置失效时间，单位秒
                .tokenValiditySeconds(60)
                //和前端name的字段保持一致
//                .rememberMeParameter("remember-me")
                //自定义登录逻辑
                .userDetailsService(userDetailsService)
                //持久层对象
                .tokenRepository(persistentTokenRepository);

        //退出登录
        http.logout()
                .logoutUrl("/logout")
                //退出登录跳转页面
                .logoutSuccessUrl("/login.html");
    }

    @Bean
    public PasswordEncoder getPw(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public PersistentTokenRepository getPersistentTokenRepository(){
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource);
        //自动建表。第一次启动时候需要，第二次启动需要注释掉
//        jdbcTokenRepository.setCreateTableOnStartup(true);
        return jdbcTokenRepository;
    }
}
