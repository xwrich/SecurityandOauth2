**课程：** [https://www.bilibili.com/video/BV1ZN411Q7d8](https://www.bilibili.com/video/BV1ZN411Q7d8)   p1 到 p30

## Spring Security 介绍

提供认证、授权、加密功能的安全框架。


### 1、用户凭证信息处理 UserDetailService

- UserDetailService

```java
public interface UserDetailsService {

    // 根据 username（唯一标识） 加载用户信息
	UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
}
```

- UserDetail   提供核心用户信息

```java
public interface UserDetails extends Serializable {

	Collection<? extends GrantedAuthority> getAuthorities();

	String getPassword();

	String getUsername();

	boolean isAccountNonExpired();

	boolean isAccountNonLocked();

	boolean isCredentialsNonExpired();

	boolean isEnabled();

}

```

实现类：**User**，注意，这里的 User 类是 spring-security 官方提供的

![请添加图片描述](https://img-blog.csdnimg.cn/0a6d2efe0a4245a095b7b6746251e992.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)




### 2、加密规则 Passwordencoder

```java
public interface PasswordEncoder {

    // 对原始密码(前端传来的“明文”，是前端md5的结果)进行编码。
    // 通常，好的编码算法应用 SHA-1 或更大的哈希值与 8 字节或更大的随机生成的盐值相结合。
	String encode(CharSequence rawPassword);

    // 检查 明文密码是否与密文密码 匹配
	boolean matches(CharSequence rawPassword, String encodedPassword);

    // 生成的密文是否需要再次被加密。用来判断密文安全性
	default boolean upgradeEncoding(String encodedPassword) {
		return false;
	}

}
```

很多实现类，官方推荐 `BCryptPasswordEncoder`

```java
@Test
void t1() {
    PasswordEncoder pa = new BCryptPasswordEncoder();
    String secret = pa.encode("engure");
    System.out.println(secret);
    System.out.println(pa.matches("engure", secret));
    System.out.println(pa.matches("123", secret));
}
```

注意：容器中没有 Passwordencoder 对象，需要注入

### 3、自定义登录

#### 1. 自定义登录逻辑（身份信息）

```java
@Configuration
public class SecurityConfig {
    /*
    创建加密编码器
     */
    @Bean
    public PasswordEncoder getPE() {
        return new BCryptPasswordEncoder();
    }
}
```

**定义登录逻辑 — 加载指定用户的信息**

- 这里为了简单假设只有一个 admin 用户
- 也可以定义多个用户，也可以连接数据库并从中检索用户

```java
@Service
public class UserDetailServiceImpl implements UserDetailsService {

    @Autowired
    private PasswordEncoder pe;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        if (!StringUtils.hasLength(username)) throw new UsernameNotFoundException("invalid username!");

        if (!"admin".equals(username)) throw new UsernameNotFoundException("user not exist!");

        String pwd = pe.encode("123");

        // 返回核心用户信息，这里的 User 是 org.springframework.security.core.userdetails 包下的！
        return new User(username, pwd, AuthorityUtils.commaSeparatedStringToAuthorityList("admin,xyz"));
    }
}
```



#### 2. 自定义登录页面及错误处理

```java
@Override
protected void configure(HttpSecurity http) throws Exception {

    // 请求授权管理
    http.authorizeRequests()
        // 授权策略： 允许所有人访问    /login.html, /login_error.html
        .antMatchers("/login.html").permitAll()
        .antMatchers("/login_error.html").permitAll()
        // 其他的请求都需要授权
        .anyRequest().authenticated();

    http.formLogin()
        // 登录页面
        .loginPage("/login.html")
        // 登录处理
        .loginProcessingUrl("/login")
        // 登录成功
        .successForwardUrl("/toMain")
        // 登录失败
        .failureForwardUrl("/toLoginError");

    // 禁用 csrf 防护
    http.csrf().disable();

}
```



#### 3. 自定义表单中用户名和密码的参数名

![请添加图片描述](https://img-blog.csdnimg.cn/8ae1d11f05874f329b337baefd004e94.png)


体现在 `UsernamePasswordAuthenticationFilter` 中：

```java
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		if (this.postOnly && !request.getMethod().equals("POST")) {
			throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
		}
		String username = obtainUsername(request);	// 使用指定的参数从请求中获取登录名
		username = (username != null) ? username : "";
		username = username.trim();
		String password = obtainPassword(request);	// 使用指定的或默认的参数从请求中获取密码
		password = (password != null) ? password : "";
		UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);
		// Allow subclasses to set the "details" property
		setDetails(request, authRequest);
		return this.getAuthenticationManager().authenticate(authRequest);
	}
```



#### 4. 自定义登录成功跳转逻辑
![请添加图片描述](https://img-blog.csdnimg.cn/198b130ce0ed4310905754958e4fdcc8.png)![请添加图片描述](https://img-blog.csdnimg.cn/46b5b7ed58fa44f6847920ecd343a1fb.png)
**之前的成功跳转：**

> **原理**：验证通过，转发到一个 POST 处理器（点进 `successForwardUrl()` 发现是用的是原生的转发）

**弊端：前后端分离项目中不能使用转发。**



修改成重定向：

```java
/*
自定义认证成功处理器：重定向到一个 url
 */

public class MyAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final String redirectUrl;

    public MyAuthenticationSuccessHandler(String redirectUrl) {
        this.redirectUrl = redirectUrl;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        response.sendRedirect(redirectUrl);
    }
}
```

使用该处理器
![请添加图片描述](https://img-blog.csdnimg.cn/0254c6596dd942b087e6f75c42184269.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)



#### 5. 自定义登录失败跳转逻辑

与 4. “登录成功” 跳转逻辑 同理，定义登录失败处理器：

```java
/*
自定义认证失败处理器：转发到某一个 url
 */

public class MyAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final String redirectUrl;

    public MyAuthenticationFailureHandler(String redirectUrl) {
        this.redirectUrl = redirectUrl;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        response.sendRedirect(redirectUrl);
    }
}
```
![请添加图片描述](https://img-blog.csdnimg.cn/3f7cdce02c8944eca1c290b157bfdbbc.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)




### 4、几个 API



#### 1. anyRequest()



```java
// 请求授权管理
http.authorizeRequests()
    // 授权策略： 允许所有人访问    /login.html, /login_error.html
    .antMatchers("/login.html").permitAll()
    .antMatchers("/login_error.html").permitAll()
    // 其他的请求都需要授权
    .anyRequest().authenticated();
```

`anyRequest()` 需要放在最后



#### 2. antMachers()

```java
public C antMatchers(String... antPatterns) {}
```

方法参数是可变参数，每个字符串都是一个 **ant 表达式**：

- `?`：匹配一个字符
- `*`：匹配 0 个或多个字符
- `**`：匹配 0 个或多个目录

示例：放行静态资源

1. 根据目录放行：`antMatchers("/js/**", "/css/**","/images/**").permitAll()`
2. 根据文件后缀名放行：`antMatchers("/**/*.png").permitAll()`

除此之外，还有一个重载方法：

```java
public C antMatchers(HttpMethod method, String... antPatterns) {}
```

第一个参数用来指定访问的方法。相同的 url 路径，只授权指定的请求方法。



#### 3.regexMachers()

```java
public C regexMatchers(String... regexPatterns) {}
public C regexMatchers(HttpMethod method, String... regexPatterns) {}
```

与 antMachers() 唯一不同的是，每个参数都是一个正则表达式。

比如：`regexMachers(".+[.]png").permitAll()`



#### 4. mvcmachers()

在配置了项目路径的情况下使用

```properties
spring.mvc.servlet.path=/xyz
```

```java
.mvcMatchers("/demo").servletPath("/xyz").permitAll()
//            /xyz/demo 
```



### 5、访问控制



#### 1. 内置的访问控制方法



进入 `permitAll()` 方法所在的类：

```java
public final class ExpressionUrlAuthorizationConfigurer<H extends HttpSecurityBuilder<H>>
      extends AbstractInterceptUrlConfigurer<ExpressionUrlAuthorizationConfigurer<H>, H> {

   static final String permitAll = "permitAll";

   private static final String denyAll = "denyAll";

   private static final String anonymous = "anonymous";

   private static final String authenticated = "authenticated";

   private static final String fullyAuthenticated = "fullyAuthenticated";

   private static final String rememberMe = "rememberMe";
```



#### 2. 根据角色与权限授权



之前配置的用户信息：（账号、密码、角色权限字符串）

![<img src="images/README/image-20211207183542498.png" alt="image-20211207183542498" style="zoom:80%;" />](https://img-blog.csdnimg.cn/dd5fe2b643bc4f7184924627f7b55d95.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)


其中的 `admin,xyz` 表示给该用户 admin 和 xyz 的权限。（注：是权限而不是角色，两者是同级关系）



**按「权限」配置授权规则**

```java
antMachers().hasAuthority()		// 一个权限
antMachers().hasAnyAuthority()	// 任一权限
```

![<img src="images/README/image-20211207190838042.png" alt="image-20211207190838042" style="zoom:80%;" />](https://img-blog.csdnimg.cn/62a63b3e79bb4f85b6050356618eb2d3.png)


表示授权给拥有 admin 权限的用户对 `docs/doc1.html` 的访问权。



**按「角色」配置授权规则**

添加角色（与添加权限有所不同）："admin,xyz,ROLE_abc,ROLE_xYz"

- 以 `ROLE_` 为前缀，后边的内容为角色标识
- 角色标识 **严格区分大小写**

```java
antMachers().hasRole()			// 一个角色
antMachers().hasAnyRole()		// 任一角色
```

 ![<img src="images/README/image-20211207190850310.png" alt="image-20211207190850310" style="zoom:80%;" />](https://img-blog.csdnimg.cn/a89ba3263d374999a53dd856cd2c53c9.png)




#### 3. 根据 ip 地址授权

```java
.antMatchers("/demo").hasIpAddress("192.168.121.2")
```

查看登录信息：

 ![<img src="images/README/image-20211207202658335.png" alt="image-20211207202658335" style="zoom: 67%;" />](https://img-blog.csdnimg.cn/e0ae5c8fd92d433e9e3b0f787fca5104.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)




#### 4. access 表达式



总结授权控制：访问 xxx 资源需要满足 xxx 条件

![<img src="images/README/image-20211207211206791.png" alt="image-20211207211206791" style="zoom:80%;" />](https://img-blog.csdnimg.cn/edd413de0fb840e18ab3d9911b934584.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)


进入“授权动作” 查看：

![<img src="images/README/image-20211207205240504.png" alt="image-20211207205240504" style="zoom:80%;" />](https://img-blog.csdnimg.cn/e03b7e359968432aa66c104076bc3bfb.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)


很多 “授权” 方法都调用了 `access()` 方法。仔细看，发现 `access()` 方法的参数是一个表达式。

![<img src="images/README/image-20211207205503835.png" alt="image-20211207205503835" style="zoom:80%;" />](https://img-blog.csdnimg.cn/2ebcd90bad854ce3b303e78354dbf2fc.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)


该表达式描述了 “授权动作”。简单使用：

```java
.antMatchers("/abc").permitAll()
.antMatchers("/abc").access("permitAll()")

.antMatchers("/xyz").hasAnyRole("admin", "normal")
.antMatchers("/xyz").access("hasAnyRole('admin','normal')")

.antMatchers("").hasIpAddress("127.0.0.1")
.antMatchers("").access("hasIpAddress('127.0.0.1')")
```

详细文档：

- https://docs.spring.io/spring-security/reference/5.6.1/servlet/authorization/expression-based.html#el-common-built-in

**acess 表达式优点**：功能更强大。原生的授权方法（比如 permitAll()，hasIpAddress() 等）不能连着写，如果要对某一个资源添加多个权限控制则需要写多个 `antMatchers().xxx`，使用 access 表达式的方式支持同时写多个授权条件比如 `access("hasRole('ROLE_USER') and hasIpAddress('10.10.10.3')")`



**高级用法：使用 access 表达式 + 自定义方法 实现授权**

示例接口：

 ![<img src="images/README/image-20211207220257535.png" alt="image-20211207220257535" style="zoom:80%;" />](https://img-blog.csdnimg.cn/2751229c3d4b4774b91ace1b0fd06066.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)


添加权限：（在`UserDetailServiceImpl`中）

 ![<img src="images/README/image-20211207220358911.png" alt="image-20211207220358911" style="zoom:80%;" />](https://img-blog.csdnimg.cn/3dd5cc8aa5d240a0a8b3ae2fbbe7e25a.png)


自定义授权方法：

```java
/*
自定义权限控制方法。
 */

@Service
public class MyAccessCtrlServiceImpl implements MyAccessCtrlService {

    @Override
    public boolean canAccess(HttpServletRequest request, Authentication authentication) {
        Object principal = authentication.getPrincipal();

        if (principal instanceof UserDetails) {
            UserDetails user = (UserDetails) principal;
            Collection<? extends GrantedAuthority> authorities =
                    user.getAuthorities();
            System.out.println("uri " + request.getRequestURI());
            System.out.println("authorities " + authorities);
            // 如果有 URI 代表的权限，那么可以访问这个 URI
            return authorities.contains(new SimpleGrantedAuthority(request.getRequestURI()));
        }

        return false;
    }
}
```

使用 access 表达式配置授权规则：

```java
.antMatchers("/access/demo").access("@myAccessCtrlServiceImpl.canAccess(request, authentication)")
```



### 6、自定义 403 响应



自定义”访问拒绝处理器“：

```java
/*
(403)拒绝访问处理器
 */

public class MyAccessDeniedHandler implements AccessDeniedHandler {

    // 处理方法
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {

        // 自定义 403 处理逻辑
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setHeader("Content-Type", "application/json;charset=utf-8");
        PrintWriter writer = response.getWriter();
        writer.write("{\"status\":\"error\", \"message\":\"权限不足，请联系管理员！\"}");
        writer.flush();
        writer.close();
    }

}

```

配置到异常处理中：

```java
@Override
    protected void configure(HttpSecurity http) throws Exception {

        ...

        // 异常处理
        http.exceptionHandling()
                .accessDeniedHandler(new MyAccessDeniedHandler());

    }
```



### 7、基于注解的权限控制



#### 1. @Secured



使用 **@Secured** 注解，代替 **.antMatchers("/secured").hasRole("abc")**

- 需要开启注解使用：**@EnableGlobalMethodSecurity(securedEnabled = true)**
- 可以修饰方法或类，判断用户是否有某个**角色**。(注意：这里是角色，而不是权限)
- 判断的角色字符串必须以 **ROLE_** 开头，并且后边的角色标识大小写敏感。
- 通常标注在 controller 的方法上，比如：

```java
/*
测试 @Secured 注解授权角色的功能
 */
@Secured("ROLE_abc")            // 同 .antMatchers("/secured").hasRole("abc")
@ResponseBody
@GetMapping("/secured")
public String securedTest() {
    return "Got secured protect!";
}
```



#### 2. @PreAuthorize / @PostAuthorize



**@PreAuthorize 与 @PostAuthorize：**

- 需要开启注解支持：**@EnableGlobalMethodSecurity(prePostEnabled = true)**
- 可用来修饰类或方法，在类（的方法）或方法执行前或后进行权限控制，前者常用后者不常用
- 通常使用前者标注 controller 的方法，进行权限控制
- 注解的参数是 **access 表达式**
- **优点：更加灵活**
- 示例：

```java
    /*
    测试 @PreAuthorize 注解
     */
    @PreAuthorize("hasRole('abc')") // 授权控制，access 授权表达式
    @ResponseBody
    @GetMapping("/prePostAuthorize")
    public String testPrePostAuthorize() {
        return "@PreAuthorize matters!";
    }
```

注：这里基于角色的权限控制的方法 hasRole 中的参数可以以 **ROLE_** 开头，即 "hasRole('ROLE_abc')" 也是正确的。



### 8、记住我功能



将用户登录的 token 持久化在数据库中，需要连接数据库

```xml
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-jdbc</artifactId>
        </dependency>
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
        </dependency>
```

```properties
# 数据源
spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver
spring.datasource.username=root
spring.datasource.password=mysql
spring.datasource.url=jdbc:mysql://localhost:3306/security
```



记住我相关配置：**在 SecurityConfig 中配置**

```java
        // 记住我
        http.rememberMe()
                // token 寿命
                .tokenValiditySeconds(60 * 60 * 12 * 3)
                // token 持久层对象。如果不配置默认持久化在内存中
                .tokenRepository(persistentTokenRepository)
                // 表单参数名
                .rememberMeParameter("remember-me");


    /*
    remember-me  token 持久化对象
     */
    @Bean
    public PersistentTokenRepository getPersistentTokenRepository() {
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();

        // 设置数据源
        jdbcTokenRepository.setDataSource(dataSource);

        // 首次启动时为我们创建表。第二次启动要注释次行。
        // jdbcTokenRepository.setCreateTableOnStartup(true);

        return jdbcTokenRepository;
    }

```

修改表单：

![\[外链图片转存失败,源站可能有防盗链机制,建议将图片保存下来直接上传(img-1uV6g7Ta-1641995129811)(images/README/image-20211208212454369.png)\]](https://img-blog.csdnimg.cn/c5d4132e8ad94b6bb994c1b514594939.png)


测试：

![\[外链图片转存失败,源站可能有防盗链机制,建议将图片保存下来直接上传(img-yzGu9Jb5-1641995129812)(images/README/image-20211208212617013.png)\]](https://img-blog.csdnimg.cn/bfea007765094d66b7ffeecaa82ddf24.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)
![<img src="images/README/image-20211208212708279.png" alt="image-20211208212708279" style="zoom:80%;" />](https://img-blog.csdnimg.cn/9ae840bf59374d2bae8dfff3437ef121.png)




### 9、与 Thymeleaf 整合



Spring Security 可以**在一些视图技术中进行控制显示效果**。比如 JSP 和 thymeleaf。

Thymeleaf 对 Spring Security 的支持都放在 `thymeleaf-extras-springsecurityX` 中（其中 X 为 Spring Security 的版本）

- https://github.com/thymeleaf/thymeleaf-extras-springsecurity



#### 1. 在 thymeleaf 中获取属性值



```xml
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-thymeleaf</artifactId>
        </dependency>
        <dependency>
            <groupId>org.thymeleaf.extras</groupId>
            <artifactId>thymeleaf-extras-springsecurity5</artifactId>
        </dependency>
```

编写 thymeleaf 待解析的页面，使用提供的属性值：

```html
<!DOCTYPE html>
<html lang="en" xmlns:sec="http://www.thymeleaf.org/extras/spring-security">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
</head>
<body>

<h1>认证信息</h1>

登录账号：<span sec:authentication="name"></span><br/>
登录账号：<span sec:authentication="principal.username"></span><br/>
凭证：<span sec:authentication="credentials"></span><br/>
权限与角色：<span sec:authentication="authorities"></span><br/>
客户端地址：<span sec:authentication="details.remoteAddress"></span><br/>
sessionId：<span sec:authentication="details.sessionId"></span><br/>

</body>
</html>
```

编写 controller 转发页面。访问：

 ![<img src="images/README/image-20211208223158716.png" alt="image-20211208223158716" style="zoom:80%;" />](https://img-blog.csdnimg.cn/eea474ad6f504f579a7771709920bca4.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)
![<img src="images/README/image-20211208223936544.png" alt="image-20211208223936544" style="zoom:80%;" />](https://img-blog.csdnimg.cn/e87534f9f1e44114bef875c7f5635990.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)


**相关类**：

- **UsernamePasswordAuthenticationToken** 及其父类 
-  **AbstractAuthenticationToken**
- **WebAuthenticationDetails**



`principle` 是 **UserDetails**

`credentials` 是凭证



#### 2. 在 thymeleaf 中进行权限判断
```html
<!DOCTYPE html>
<html lang="en"
      xmlns:sec="http://www.thymeleaf.org/extras/spring-security"
>
<head>
    <meta charset="UTF-8">
    <title>Title</title>
</head>
<body>

<h1>权限判断</h1>

通过权限判断：
<button sec:authorize="hasAuthority('/insert')">新增</button>
<button sec:authorize="hasAuthority('/delete')">删除</button>
<button sec:authorize="hasAuthority('/update')">修改</button>
<button sec:authorize="hasAuthority('/select')">查看</button>
<br/>
通过角色判断：
<button sec:authorize="hasRole('abc')">新增</button>
<button sec:authorize="hasRole('abc')">删除</button>
<button sec:authorize="hasRole('abc')">修改</button>
<button sec:authorize="hasRole('abc')">查看</button>

</body>
</html>
```

定义权限：

![<img src="images/README/image-20211208225625252.png" alt="image-20211208225625252" style="zoom:80%;" />](https://img-blog.csdnimg.cn/1e50b90cb833462085696dff5b86f181.png)


访问网页：

 ![<img src="images/README/image-20211208225526936.png" alt="image-20211208225526936" style="zoom:80%;" />](https://img-blog.csdnimg.cn/21512d02684c479bac862cdd61502ca6.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)


发现按照权限判断时只有新增和查看两个按钮，说明权限判断失败的标签不能被渲染。



### 10、退出登录功能



默认情况下（不使用 http.logout() 时），提供 **/logout** 登出功能。



若要定制登出地址和登出成功地址：

 ![<img src="images/README/image-20211208230957528.png" alt="image-20211208230957528" style="zoom:80%;" />](https://img-blog.csdnimg.cn/df058fc7739b4bdcb60a351e6db85e56.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)
![<img src="images/README/image-20211208231142668.png" alt="image-20211208231142668" style="zoom:80%;" />](https://img-blog.csdnimg.cn/f985750e8c65482996d33d47e7e331af.png)




**查看源码：**

查看 http.logout() 的返回值，**LogoutConfigurer** 类，

发现上边使用传递 URL 的方式来处理登出相关逻辑实际是由两个 Handler 来处理的，我们也可以通过自定义 handler 的方式处理登出和登出成功逻辑：**仿写已有的 xxxHandler**
![<img src="images/README/image-20211208233008683.png" alt="image-20211208233008683" style="zoom:80%;" />](https://img-blog.csdnimg.cn/590ecd0a765e4c6dab4f0476a7b83bc6.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)




**分析使用的 Handler：**

**1、LogoutHandler 处理登出逻辑**

默认使用的实现类：**SecurityContextLogoutHandler**，该类的实现：
![<img src="images/README/image-20211208232357538.png" alt="image-20211208232357538" style="zoom:80%;" />](https://img-blog.csdnimg.cn/c05d057136f14ffa8a1f797025506aff.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)


处理登录逻辑：1. 让 session 失效   2. 清除认证信息。**默认情况下连这都会执行**


**2、LogoutSuceessHandler 登出成功处理器**

默认 **SimpleUrlLogoutSuccessHandler**，处理逻辑：

 ![<img src="images/README/image-20211208233440277.png" alt="image-20211208233440277" style="zoom:80%;" />](https://img-blog.csdnimg.cn/401669d031fb4c43b126e480123bd2a6.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)




### 11、csrf 防护



跨站请求伪造。

小 A 访问 hacker 的网站并在不知不觉中点击了某个银行的转账链接（hacker 的圈套）比如 `http://xxxbank.cn/transfer?to=hacker&money=20000`，如果小 A 登录该银行网站并且未注销，那么此时小 A 与银行网站的回话未结束浏览器保存回话 token，会导致点击 hacker 的链接会默认带上与银行网站的回话 token 造成 hacker 得逞。

解决方法：

- 将 token 放置在请求头中，排除发送请求自动携带 cookie 的问题
- cookie方案下的 post 表单提交要求用户携带另一个 _csrf token（spring security 的 csrf 防护）



框架学习时关闭 csrf 防护，生产环境下，需要开启防护，**http.csrf().disable()**

一般在发送请求时要求使用 post 表单的方式，需要携带 “个性化信息”，让服务器知道我们的身份，登录示例：

![<img src="images/README/image-20211209001416543.png" alt="image-20211209001416543" style="zoom:80%;" />](https://img-blog.csdnimg.cn/af1cb4f612f34dae9fc6aab8e1a8469c.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)


我们额外携带的信息不能是 cookie，上例是发送请求时需要携带嵌在网页表单中的 crsf token。