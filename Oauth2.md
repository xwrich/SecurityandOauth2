[SpringSecurity学习记录【一】](https://blog.csdn.net/qq_44723773/article/details/122463188)


- [x] 开启 csrf 防护
- [x] 定制登录、登出功能
- [x] 基于注解的授权模式
- [x] 使用数据库进行身份认证（建表、手动赋值权限）

# Oauth2

## 1、简介

OAUTH 协议为用户资源的授权提供了一个**安全的、开放而又简易**的标准。同时，任何第三方都可以使用OAUTH认证服务，任何服务提供商都可以实现自身的OAUTH认证服务，因而OAUTH是开放的。业界提供了OAUTH的多种实现如PHP、JavaScript，Java，Ruby等各种语言开发包，大大节约了程序员的时间，因而OAUTH是简易的。互联网很多服务如Open API，很多大公司如Google，Yahoo，Microsoft等都提供了OAUTH认证服务，这些都足以说明OAUTH标准逐渐成为开放资源授权的标准。

Oauth协议目前发展到2.0版本，1.0版本过于复杂，2.0版本已得到广泛应用。

参考：https://baike.baidu.com/item/oAuth/7153134?fr=aladdin

Oauth 协议：https://tools.ietf.org/html/rfc6749

![<img src="images/03Oauth/image-20211217140654041.png" alt="image-20211217140654041" style="zoom:80%;" />](https://img-blog.csdnimg.cn/be5dcf5f5f2041408c78080abd4be8ac.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)


### 1）角色

- **客户端**：本身不存储资源，需要资源拥有者的授权去请求资源服务器的资源，比如 Android 客户端、Web 客户端（浏览器端）、微信客户端等
- **资源拥有者**：通常是用户，也可以是应用程序，即该资源的的拥有者
- **授权服务器（也称认证服务器）**：对资源请求者的身份进行认证授权。客户端想要访问资源，需要先经过**认证服务器资源拥有者**的授权
- **资源服务器**：存储资源的服务器



### 2）常用术语



- **客户凭证（client credentials）**：客户读端的 clientId 和密码用于认证客户
- **令牌（token）**：授权服务器认证客户身份后颁发的访问令牌
- **作用域（scopes）**：客户请求访问令牌时，资源拥有者额外指定的细分权限（permission）



### 3）令牌类型



- **授权码：**用于交换获取访问令牌和刷新令牌
- **访问令牌：**用于代表一个用户或服务直接去访问收保护的资源
- **刷新令牌：**用于去授权服务器**获取**一个刷新访问令牌
- **BearerToken：**不管谁拿到该 Token 都可以访问资源
- **Proof of Possession(POP) Token：**可以校验 client 是否对 Token 有明确的拥有权



### 3）优缺点

**优点：**

更安全，客户端不接触用户密码，服务器端更易集中保护

广泛传播并被持续采用

短寿命和封装的token

资源服务器和授权服务器解耦

集中式授权，简化客户端

HTTP/JSON友好，易于请求和传递token

考虑多种客户端架构场景

客户可以具有不同的信任级别

**缺点：**

协议框架太宽泛，造成各种实现的兼容性和互操作性差

不是一个认证协议，本身并不能告诉你任何用户信息。



## 2、授权模式



### 1）授权码模式 

![<img src="images/03Oauth/image-20211220195549360.png" alt="image-20211220195549360" style="zoom:150%;" />](https://img-blog.csdnimg.cn/e690a23c29644d19b84777488f7cf5d6.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)


### 2）简化授权模式

![<img src="images/03Oauth/image-20211220195605799.png" alt="image-20211220195605799" style="zoom:150%;" />](https://img-blog.csdnimg.cn/eb48a176bd054489a5678941ce38486c.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)


### 3）密码模式

![<img src="images/03Oauth/image-20211220195639904.png" alt="image-20211220195639904" style="zoom:150%;" />](https://img-blog.csdnimg.cn/1274a4f4402f4bde9b2cb03774464c7b.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)


### 4）客户端模式

![<img src="images/03Oauth/image-20211220195654483.png" alt="image-20211220195654483" style="zoom:150%;" />](https://img-blog.csdnimg.cn/c6a56f8738384edc90819913eb704a05.png)


### 5）刷新令牌

![<img src="images/03Oauth/image-20211220195703237.png" alt="image-20211220195703237" style="zoom:150%;" />](https://img-blog.csdnimg.cn/b151252990b141fba2264701f3e27165.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)




## 3、Spring Security Oauth2



**小插曲：授权服务器：**

 ![<img src="images/03Oauth/image-20211217203748894.png" alt="image-20211217203748894" style="zoom:80%;" />](https://img-blog.csdnimg.cn/13c4dae8d7b845f8971c2c0f43764e60.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)


- `Authentication Endpoint`：授权端点、进行授权

- `Token Endpoint`：令牌端点，经过授权拿到对应的 Token

- `Introspection Endpoint`：校验端点，校验 Token 的合法性

- `Revocation Endpoint`：撤销端点，撤销授权

  

### 1）Spring Securit Oauth2 架构

![<img src="images/03Oauth/image-20211217203529013.png" alt="image-20211217203529013"  />](https://img-blog.csdnimg.cn/b4833e7d346d406fb3ea9a156c113549.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)


**流程：**

1. 用户访问，此时没有Token。Oauth2RestTemplate 会报错，这个报错信息会被 Oauth2ClientContextFilter 捕获并重定向到认证服务器

2. 认证服务器通过 Authorization Endpoint 进行授权，并通过 AuthorizationServerTokenServices 生成授权码并返回给客户端

3. 客户端拿到授权码去认证服务器通过 Token Endpoint 调用 AuthorizationServerTokenServices 生成 Token 并返回给客户端

4. 客户端拿到 Token 去资源服务器访问资源，一般会通过 Oauth2AuthenticationManager 调用 ResourceServerTokenServices 进行**校验**。校验通过可以获取资源



### 2）授权码模式

#### 简单项目搭建



依赖：

```xml
    <properties>
        <java.version>11</java.version>
        <spring-cloud.version>Greenwich.SR2</spring-cloud.version>
    </properties>


    <dependencies>

        <!-- 使用 spring-cloud 中的依赖 -->
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-oauth2</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-security</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>org.springframework.cloud</groupId>
                <artifactId>spring-cloud-dependencies</artifactId>
                <version>${spring-cloud.version}</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>

```



定义用户登录逻辑

```java
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        String pwd = passwordEncoder.encode("123123");
        return new EUser("admin", pwd,
                AuthorityUtils.commaSeparatedStringToAuthorityList("admin"));
    }
}
```

其中使用了自定义的用户信息类：

```java
public class EUser implements UserDetails {

    private String username;
    private String password;
    private List<GrantedAuthority> authorities;

    public EUser(String username, String password, List<GrantedAuthority> authorities) {
        this.username = username;
        this.password = password;
        this.authorities = authorities;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
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
```



配置 SpringSecurity

```java
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // 测试环境下，关闭 csrf 防护
        http.csrf().disable();

        http.formLogin().permitAll();

        http.authorizeRequests()
                .antMatchers("/login/**", "/oauth/**", "/logout/**").permitAll()
                .anyRequest().authenticated();

    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
```



配置授权服务器

```java
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

        clients.inMemory()
                // client-id
                .withClient("admin")
                // client-secret
                .secret(passwordEncoder.encode("123456"))
                // token 的有效期
                .accessTokenValiditySeconds(3600)
                // redirect_uri，用于授权成功后跳转
                .redirectUris("http://www.baidu.com")
                // 申请的权限范围
                .scopes("all")
                // grant_type，授权类型
                .authorizedGrantTypes("authorization_code");

    }
}
```



**配置资源服务器**

```java
@Configuration
@EnableResourceServer
public class ResourceServer extends ResourceServerConfigurerAdapter {
    @Override
    public void configure(HttpSecurity http) throws Exception {

        http.authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .requestMatchers().antMatchers("/user/**");

    }
}
```



编写接口，模拟资源：

```java
@RestController
@RequestMapping("/user")
public class UserController {

    /*
    获取当前用户
     */
    @RequestMapping("/getCurrentUser")
    public Object current(Authentication authentication) {
        return authentication.getPrincipal();
    }

}
```



#### 手动访问



1、浏览器访问：

[http://localhost:8080/oauth/authorize?response_type=code&client_id=admin&redirect_uri=http://www.baidu.com&scope=all](http://localhost:8080/oauth/authorize?response_type=code&client_id=admin&redirect_uri=http://www.baidu.com&scope=all)



2、进入登录页面，输入帐号密码。



3、验证通过后，来到授权页：

![](https://img-blog.csdnimg.cn/51bc9805d79c469cb98351531e78b1e4.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)




4、授权后跳转页面，同时会携带**授权码**：

 ![](https://img-blog.csdnimg.cn/5ea15ad0c209416183356120c1672250.png)




5、使用 Postman 发送请求、获取**资源请求码**：

**一、**

![在这里插入图片描述](https://img-blog.csdnimg.cn/cce59c7d752a47eca607d71e44d3d51d.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)



**二、**
![在这里插入图片描述](https://img-blog.csdnimg.cn/20ba490c92a347fe9e59256582bbf6fc.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)

6、使用 **访问码** 访问资源：

![在这里插入图片描述](https://img-blog.csdnimg.cn/18816d55c0ca44549c91a031ba0caa8b.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)


### 3）密码模式



1、配置授权服务器的**授权类型**：

![](https://img-blog.csdnimg.cn/3b91e8dbec2947afbf8abf287fea8d8b.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)




2、添加组件：（下一步需要用到）

![在这里插入图片描述](https://img-blog.csdnimg.cn/b398a8d75f31465dadac894e2691e5c9.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)


3、授权服务器方法重写：

```java
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UserDetailsService userDetailsService;  // 我们的实现类 UserDetailsServiceImpl

    // 使用密码模式所需配置
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager)
                .userDetailsService(userDetailsService);
    }
    
    ....
}
```



**手动模拟密码模式：**

**一、**

![在这里插入图片描述](https://img-blog.csdnimg.cn/2ba08ad855214d57bca3ccf12e278816.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)


**二、**

![](https://img-blog.csdnimg.cn/6fa29487913a4b8bb43b990eb1cde885.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)




### 4）使用 redis 存储 token



添加依赖：

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>
```





配置 oauth 提供的用于 redis token 操作的组件：

```java
@Configuration
public class RedisConfig {

    @Autowired
    private RedisConnectionFactory redisConnectionFactory;

    /*
    创建用于存储 token 的组件
     */
    @Bean
    public TokenStore tokenStore() {
        return new RedisTokenStore(redisConnectionFactory);
    }

}
```



修改一处配置：

![在这里插入图片描述](https://img-blog.csdnimg.cn/6602a4ab232848f2b26a1b7ebbf55bab.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)




登录后，查看 reids：

![在这里插入图片描述](https://img-blog.csdnimg.cn/f6d87d4ea4bc41999dc825ba18d8e047.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)






## 2、JWT



### 1）常见的认证机制

1. HTTP Basic Auth

   Basic Auth 是配合 RESTful API 使用的最简单的认证方式，只需提供用户名密码即可，但由于有把用户名密码暴露给第三方客户端的风险，在生产环境下被使用的越来越少

2. Cookie Auth

   Cookie 认证机制就是为一次请求认证在服务端创建一个 Session 对象，同时在客户端的浏览器端创建了一个 Cookie 对象；通过客户端带上来 Cookie 对象来与服务器端的 session 对象匹配来实现状态管理的。默认的，当我们关闭浏览器的时候，cookie 会被删除。但可以通过修改 cookie 的 expire time 使 cookie 在一定时间内有效。

3. OAuth

   OAuth（开放授权,Open Authorization）是一个开放的授权标准，允许用户让第三方应用访问该用户在某一 web 服务上存储的私密的资源（如照片，视频，联系人列表），而无需将用户名和密码提供给第三方应用。如网站通过微信、微博登录等，主要用于第三方登录。

   缺点：过重

4. Token Auth

> **比第一种方式更安全，比第二种方式更节约服务器资源，比第三种方式更加轻量。**
> 具体，Token Auth的**优点**（Token机制相对于Cookie机制又有什么好处呢？）：
>
> 1. 支持**跨域**访问: Cookie是不允许垮域访问的，这一点对Token机制是不存在的，前提是传输的用户认证信息通过HTTP头传输. 
> 2. 无状态(也称：服务端可扩展行)：Token 机制在服务端不需要存储 session 信息，因为 Token 自身包含了所有登录用户的信息，只需要在客户端的 cookie 或本地介质存储状态信息. 
> 3. 更适用 CDN: 可以通过内容分发网络请求你服务端的所有资料（如：javascript，HTML,图片等），而你的服务端只要提供API即可. 
> 4. 去耦: 不需要绑定到一个特定的身份验证方案。Token可以在任何地方生成，只要在你的API被调用的时候，你可以进行Token生成调用即可. 
> 5. 更**适用于移动应用**: 当你的客户端是一个原生平台（iOS, Android，Windows 10等）时，Cookie是不被支持的（你需要通过Cookie容器进行处理），这时采用Token认证机制就会简单得多。
> 6. **CSRF**：因为不再依赖于Cookie，所以你就不需要考虑对CSRF（跨站请求伪造）的防范。
> 7. 性能: 一次网络往返时间（通过数据库查询session信息）总比做一次 HMACSHA256 计算的 Token 验证和解析要费时得多
> 8. 不需要为登录页面做特殊处理：如果你使用Protractor 做功能测试的时候，不再需要为登录页面做特殊处理. 
> 9. 基于标准化：你的API可以采用标准化的 JSON Web Token (JWT). 这个标准已经存在多个后端库（.NET, Ruby, Java,Python, PHP）和多家公司的支持（如：Firebase，Google，Microsoft）.



### 2）什么是JWT?

JSON Web Token (JWT) 是一个开放的行业标准（RFC 7519）。

它定义了一种简介的、自包含的协议格式，用于在通信双方**传递 json** 对象，传递的信息经过数字签名可以被验证和信任。

JWT可以使用 HMAC 算法或使用 RSA 的公钥/私钥对来签名，防止被篡改。



- 官网：[https://jwt.io](https://jwt.io)

- 标准：[https://tools.ietf.org/html/rfc7519](https://tools.ietf.org/html/rfc7519)



`优点`：

1. jwt 基于 json，非常方便解析。
2. 可以在令牌中自定义丰富的内容，易扩展。
3. 通过非对称加密算法及数字签名技术，JWT 防止篡改，**安全性高**。
4. 资源服务使用 JWT 可不依赖认证服务即可完成授权。

`缺点`：

1. JWT 令牌较长，占存储空间比较大。



#### JWT 组成

**1、头部**

描述 JWT 最基本的信息，例如其类型以及签名算法（如 `HMAC SHA256 或 RSA`）等。

可以被表示成一个` json 对象`

```json
{
    "alg": "HS256",
    "typ": "JWT"
}
```

- `typ` 类型
- `alg` 签名算法



对其进行 **Base64 编码**：

![在这里插入图片描述](https://img-blog.csdnimg.cn/725ecd2318fe4759ac1b29fd027becd0.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)





**2、负载**



https://jwt.io/introduction



存放有效信息的地方，包含三部分：



1. 标准中注册的声明（建议但不强制使用）

   - `iss` jwt 签发者
   - `sub` jwt 面向的用户
   - `aud` 接受 jwt 的一方
   - `iat` jwt 签发时间
   - `exp` jwt 的过期时间（必须大于签发时间）
   - `nbf` 定义在什么时间之前，该 jwt 都是不可用的
   - `jti` jwt 的唯一身份表示，主要用来作为一次性 token，从而回避重放攻击

2. 公共的声明

   These can be defined at will by those using JWTs. But to avoid collisions they should be defined in the [IANA JSON Web Token Registry](https://www.iana.org/assignments/jwt/jwt.xhtml) or be defined as a URI that contains a collision resistant namespace.



> Claim Names can be defined at will by those using JWTs.  However, in
> order to prevent collisions, any new Claim Name should either be
> registered in the [IANA "JSON Web Token Claims" registry](https://www.iana.org/assignments/jwt/jwt.xhtml) established
> by Section 10.1 or be a Public Name: a value that contains a
> Collision-Resistant Name.  In each case, the definer of the name or
> value needs to take reasonable precautions to make sure they are in
> control of the part of the namespace they use to define the Claim
> Name.
>
> https://datatracker.ietf.org/doc/html/rfc7519#section-4.2



3. 私有的声明

   These are the custom claims created to share information between parties that agree on using them and are neither *registered* or *public* claims.



> A producer and consumer of a JWT MAY agree to use Claim Names that
> are Private Names: names that are not Registered Claim Names
> (Section 4.1) or Public Claim Names (Section 4.2).  Unlike Public
> Claim Names, Private Claim Names are subject to collision and should
> be used with caution.
>
> https://datatracker.ietf.org/doc/html/rfc7519#section-4.3



比如：
![在这里插入图片描述](https://img-blog.csdnimg.cn/3514391acb7f4cfba8ea38c1e4b804ad.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)


**3、签名**



需要的内容：

1. encoded header
2. encoded payload
3. a secret
4. the algorithm specified in the header



加密公式：`加密算法 + 密钥` 对 `"encoded header . encoded payload"` 加密



例如，使用 HS256 加密：

```java
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret)
```



该签名用于验证消息是否在此过程中被更改，并且，在使用私钥签名的情况下，它还可以验证JWT的发送方是否是它所说的发送方。



注意：`secret` 是保存在服务端的，`jwt` 也是由服务端生成并签发的。`secret` 使用来签发和验证 `jwt` 的，所以他就是服务器的私钥，任何情况下都不应该流露出去。



**4、将他们连起来**



将三部分用 `.` 连接起来构成了最终的 jwt，比如：

```
eyJhbGciOiJIUzUxMiJ9.eyJsb2dpbl91c2VyX2tleSI6IjNhNDQ3MjkwLTE3OWItNDc1MS04MTUxLTViZTFmZTQ4YTNjZCJ9.yCJ-yoa_Y85TytNgdtc2oczW1HNA0EG1W0VWqY9LKigDt6_QXtqpfrSgbwMY6oP5g47Aiy0xSE0JcE_kx0DiwA
```





### 3）简单使用 jwt



引入依赖：

```xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt</artifactId>
    <version>0.9.0</version>
</dependency>
```



#### （1）签发 jwt

```java
@Test
void testCreateJWT() {
    JwtBuilder builder = Jwts.builder()
            .setId("666")   // jti 标识
            .setSubject("Jack") // sub 主体
            .setIssuedAt(new Date())    // ita 创建日期
            .signWith(SignatureAlgorithm.HS256, "abcd");	// 算法 + 密钥

    String jwt = builder.compact();
    System.out.println(jwt);
    System.out.println("-------------");

    String[] arr = jwt.split("\\.");
    System.out.println(arr[0]);
    System.out.println(arr[1]);
    System.out.println(arr[2]);

}
```



#### （2）验证 jwt

```java
@Test
public void parseToken() {
    String token = "eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI2NjYiLCJzdWIiOiJKYWNrIiwiaWF0IjoxNjQwNTAxMTk2fQ.tccNEnVDZ9FTmoTiDXh4NTuccMP6HleAPn_LC5YLbDA";

    Claims claims = Jwts.parser()
            .setSigningKey("abcd")
            .parseClaimsJws(token)
            .getBody();

    System.out.println(claims.getId());
    System.out.println(claims.getSubject());
    System.out.println(claims.getIssuedAt());
}
```



#### （3）失效判断



```java
@Test
public void createTokenWithExp() {
    long now = new Date().getTime();
    long exp = now + 60 * 1000;
    JwtBuilder builder = Jwts.builder()
        .setIssuedAt(new Date(now))
        .setExpiration(new Date(exp))	// 定义带有过期时间的 token
        .signWith(SignatureAlgorithm.HS256, "abcd");

    String jwt = builder.compact();
    System.out.println(jwt);
}

@Test
public void parseTokenWithExp() {
    String token = "eyJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2NDA1MDM1ODcsImV4cCI6MTY0MDUwMzY0N30.PGpZeSsbDIL0zTK1XPJBNwzwg4oBCT0iVIdoqiMthEE";

    Claims claims = Jwts.parser()
        .setSigningKey("abcd")
        .parseClaimsJws(token)
        .getBody();

    System.out.println("签发时间"+claims.getIssuedAt());

    System.out.println("过期时间"+claims.getExpiration());	// 获取过期时间。如果过期会报错
    //过期异常：io.jsonwebtoken.ExpiredJwtException: JWT expired at 2021-12-26T15:27:27Z. Current time: 2021-12-26T15:27:27Z, a difference of 732 milliseconds.  Allowed clock skew: 0 milliseconds.

    System.out.println("当前时间"+new Date());

}

```



#### （4）自定义声明


```java
/*
创建带有自定义声明的 token
 */

@Test
public void createTokenWithClaims() {

    Map<String, Object> claims = new HashMap<>();
    claims.put("user-id", "00ab-1123-4566-abcc");
    claims.put("logo", "xxx.jpg");

    JwtBuilder builder = Jwts.builder()
            .addClaims(claims)
            .signWith(SignatureAlgorithm.HS256, "abcd");

    String jwt = builder.compact();
    System.out.println(jwt);
}

/*
解析带有 自定义声明 的 token
 */

@Test
public void parseTokenWithClaims() {

    String token = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyLWlkIjoiMDBhYi0xMTIzLTQ1NjYtYWJjYyIsImxvZ28iOiJ4eHguanBnIn0.vL4T31n-kmD2eOAPPKgGraftqNgEt_Ia8WgavmEWlJ0";

    Claims claims = Jwts.parser()
            .setSigningKey("abcd")
            .parseClaimsJws(token)
            .getBody();

    System.out.println(claims.get("user-id"));
    System.out.println(claims.get("logo"));
}
```





### 4）与 Spring Security Oauth2 整合



#### （1）简单整合



与 `3、` 中的项目整合，不使用 redis 存储 token，使用密码模式



1、去除 redis 配置

2、添加配置类 `JwtTokenCofig`：

```java
@Configuration
public class JwtTokenConfig {

    @Bean
    public TokenStore jwtTokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    /*
    Helper that translates between JWT encoded token values and OAuth authentication information (in both directions)
     */

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
        // JWT使用的密钥
        jwtAccessTokenConverter.setSigningKey("my_key");
        return jwtAccessTokenConverter;
    }


}

```



3、修改授权服务器配置：

![在这里插入图片描述](https://img-blog.csdnimg.cn/e796da5d682342fe8d746ed013fb28d6.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)




4、获取访问码（此时是密码模式）：

```json
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NDA1MTA4MDcsInVzZXJfbmFtZSI6ImFkbWluIiwiYXV0aG9yaXRpZXMiOlsiYWRtaW4iXSwianRpIjoiYTE5OGM4YTQtYmQ0Mi00NGUzLTkyZGYtZWNhZjUxY2M5OTRiIiwiY2xpZW50X2lkIjoiYWRtaW4iLCJzY29wZSI6WyJhbGwiXX0.h8GAVM1R9ZMxWrxplrth1s_ik32mmoVLJyR3Efuy2Js",
    "token_type": "bearer",
    "expires_in": 3599,
    "scope": "all",
    "jti": "a198c8a4-bd42-44e3-92df-ecaf51cc994b"
}
```



5、查看生成的 token： https://jwt.io/#debugger-io

![在这里插入图片描述](https://img-blog.csdnimg.cn/07c5b20d3b10420b9e06ddaeb3991417.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)






#### （2）扩展 JWT 内容

即自定义声明



1、创建增强器，并注册该组件

```java
public class JwtTokenEnhancerConfig implements TokenEnhancer {

    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {

        Map<String, Object> info = new HashMap<>();
        info.put("my_key", "my_val");   // 自定义声明

        ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(info);
        return accessToken;
    }
}
```



2、使用该组件
![在这里插入图片描述](https://img-blog.csdnimg.cn/8e8d8f2ae5ff4b3f8faed1c61fd21dd4.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)




3、验证生成的 access_token



![在这里插入图片描述](https://img-blog.csdnimg.cn/5dc532b4c3504211ad83a17ebd870670.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)




#### （3）解析 JWT



通过 `jjwt` 解析 jwt 中的内容：



从请求头中解析 jwt：

```java
@RequestMapping("/getCurrentUser")
public Object current(Authentication authentication,
                      HttpServletRequest request) {
    // return authentication.getPrincipal()

    String authorization = request.getHeader("Authorization");
    String token = authorization.substring(authorization.indexOf("bearer") + 7);
    // Authorization: "bearer xxxx"

    return Jwts.parser()
            .setSigningKey("my_key".getBytes(StandardCharsets.UTF_8))
            .parseClaimsJws(token)
            .getBody();
}
```



先获取访问码，再进行资源访问：

![在这里插入图片描述](https://img-blog.csdnimg.cn/b8c99cb4d40a481f8a143c524306d03b.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)




#### （4）刷新令牌



配置授权类型：

```java
.authorizedGrantTypes("password", "refresh_token", "authorization_code");  // 允许多个授权类型并存
```



1、获取访问码，同时会给出刷新码：

![在这里插入图片描述](https://img-blog.csdnimg.cn/89f94a6f26354357a7e5f9fd460447a6.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)


```json
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiJhZG1pbiIsInNjb3BlIjpbImFsbCJdLCJteV9rZXkiOiJteV92YWwiLCJleHAiOjE2NDA1MTQ1NjUsImF1dGhvcml0aWVzIjpbImFkbWluIl0sImp0aSI6IjI0NWE4MzIzLTcwZmMtNDZkYi05MTAxLWM0MjQxOTYxYzIzMCIsImNsaWVudF9pZCI6ImFkbWluIn0.KiRPNCiOSnS04FbZQya9XYcNwW8DA6M9gpTNTNch97Q",
    "token_type": "bearer",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiJhZG1pbiIsInNjb3BlIjpbImFsbCJdLCJhdGkiOiIyNDVhODMyMy03MGZjLTQ2ZGItOTEwMS1jNDI0MTk2MWMyMzAiLCJteV9rZXkiOiJteV92YWwiLCJleHAiOjE2NDMxMDI5NjUsImF1dGhvcml0aWVzIjpbImFkbWluIl0sImp0aSI6ImQyZjkwMDg1LTVjM2EtNDBmNS1hYzI2LWE2NWFlYzU4MTc5MSIsImNsaWVudF9pZCI6ImFkbWluIn0.jxwTYuI3hfSn2ky9b4p0NqjctHQmybzMPSjfXSAimjs",
    "expires_in": 3599,
    "scope": "all",
    "my_key": "my_val",
    "jti": "245a8323-70fc-46db-9101-c4241961c230"
}
```



2、使用刷新码获取访问码：
![在这里插入图片描述](https://img-blog.csdnimg.cn/19a3f8dbfaf64521ad042a22a5bcb029.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBA546L6I-c6bif,size_20,color_FFFFFF,t_70,g_se,x_16)


注意：此时请求头依旧需要使用 `Basic Authorization`