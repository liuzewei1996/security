package com.liu.security.config;

import com.liu.security.entity.User;
import com.liu.security.service.UserService;
import com.liu.security.util.CommunityUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.rememberme.InMemoryTokenRepositoryImpl;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserService userService;

    @Override
    public void configure(WebSecurity web) throws Exception {
        // 忽略静态资源的访问
        web.ignoring().antMatchers("/resources/**");
    }

    // AuthenticationManager: 认证的核心接口.
    // AuthenticationManagerBuilder: 用于构建AuthenticationManager对象的工具.
    // ProviderManager: AuthenticationManager接口的默认实现类.
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 内置的认证规则
        // auth.userDetailsService(userService).passwordEncoder(new Pbkdf2PasswordEncoder("12345"));//默认的加盐的处理

        // 自定义认证规则
        // AuthenticationProvider: ProviderManager持有一组AuthenticationProvider,每个AuthenticationProvider负责一种认证.
        //  包含一组认证：如有很多种认证方式：账号密码，微信，手机，邮箱，刷脸等等。
        // 委托模式: ProviderManager将认证委托给AuthenticationProvider.
        auth.authenticationProvider(new AuthenticationProvider() {
            // Authentication: 用于封装认证信息的接口,不同的实现类代表不同类型的认证信息.
            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                String username = authentication.getName();
                String password = (String) authentication.getCredentials();

                User user = userService.findUserByName(username);
                if (user == null) {
                    throw new UsernameNotFoundException("账号不存在!");
                }

                password = CommunityUtil.md5(password + user.getSalt());
                if (!user.getPassword().equals(password)) {
                    throw new BadCredentialsException("密码不正确!");
                }

                // 三个参数; principal: 主要信息; credentials: 证书; authorities: 权限;
                return new UsernamePasswordAuthenticationToken(user, user.getPassword(), user.getAuthorities());
            }

            // 当前的AuthenticationProvider接口支持哪种类型的认证.
            @Override
            public boolean supports(Class<?> aClass) {
                // UsernamePasswordAuthenticationToken: Authentication接口的常用的实现类.
                return UsernamePasswordAuthenticationToken.class.equals(aClass);
            }
        });
    }

    //授权；SecurityConfig类继承了WebSecurityConfigurerAdapter；
    // 这里子类（此类）覆盖掉父类WebSecurityConfigurerAdapter的授权逻辑，自己实现，可以避开spring security默认的登录页面
    //注：父类WebSecurityConfigurerAdapter的授权逻辑是任何请求全部拦截
    // http.authorizeRequests().anyRequest()).authenticated().and()).formLogin().and()).httpBasic();
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 登录相关配置
        http.formLogin()//登录表单配置
                .loginPage("/loginpage")//登录页面，在homeController中为loginpage请求
                .loginProcessingUrl("/login")//提交表单时处理这个请求的路径是什么，以便拦截这个路径；这个路径在login.html页面中有配置
                .successHandler(new AuthenticationSuccessHandler() {//成功时处理一些事情
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect(request.getContextPath() + "/index");//重定向到首页
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {//失败时处理一些事情
                    //失败时需要回到登录页面并且给一些错误提示：
                    //此处失败不可重定向到登录页面：重定向，客户端会发一个新的请求，就不好向这个新的请求传递参数
                    //只能用跨请求的cookie，session去传；比较麻烦
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
                        request.setAttribute("error", e.getMessage());
                        //可以将参数绑定到request上，把请求转发到登录页面上去（协作关系）；转发与重定向不一样，转发是一个请求之内的
                        //当前处于hendler方法中，不得不使用转发；不能返回一个模板路径（不是Controller中，不能识别）
                        request.getRequestDispatcher("/loginpage").forward(request, response);
                    }
                });

        // 退出相关配置
        http.logout()
                .logoutUrl("/logout")
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect(request.getContextPath() + "/index");
                    }
                });

        // 授权配置
        http.authorizeRequests()
                .antMatchers("/letter").hasAnyAuthority("USER", "ADMIN")
                .antMatchers("/admin").hasAnyAuthority("ADMIN")//仅管理员权限才能访问
                .and().exceptionHandling().accessDeniedPage("/denied");//权限不匹配时的页面

        // 增加Filter,处理验证码；
        // 验证码在账号密码之前验证，验证码不对，就不用验证账号密码了
        http.addFilterBefore(new Filter() {
            @Override
            public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
                HttpServletRequest request = (HttpServletRequest) servletRequest;//（servletRequest是HttpServletRequest的父接口）
                HttpServletResponse response = (HttpServletResponse) servletResponse;
                if (request.getServletPath().equals("/login")) {//登录请求才去拦截
                    String verifyCode = request.getParameter("verifyCode");
                    if (verifyCode == null || !verifyCode.equalsIgnoreCase("1234")) {//简化，设为1234；
                        request.setAttribute("error", "验证码错误!");
                        request.getRequestDispatcher("/loginpage").forward(request, response);
                        return;
                    }
                }
                // 让请求继续向下执行.执行后面的filter或其他（可能有多个filter）
                filterChain.doFilter(request, response);
            }
        }, UsernamePasswordAuthenticationFilter.class);

        // 记住我
        http.rememberMe()
                .tokenRepository(new InMemoryTokenRepositoryImpl())//它自带的实现类，存到了硬盘中；可以自定义实现类，比如存到redis内存中
                .tokenValiditySeconds(3600 * 24)
                .userDetailsService(userService);

    }
}
