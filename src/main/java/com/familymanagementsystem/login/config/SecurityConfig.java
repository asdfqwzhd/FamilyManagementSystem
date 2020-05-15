package com.familymanagementsystem.login.config;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();
		http.authorizeRequests().anyRequest().authenticated()// 所有请求必须认证过才能访问[没有配置MyFilter，DecisionManager之前]
				.and().formLogin().usernameParameter("username").passwordParameter("password")
				// 真正的登录接口，必须是key-value形式
				.loginProcessingUrl("/login").successHandler(new AuthenticationSuccessHandler() {
					@Override
					public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
							Authentication authentication) throws IOException, ServletException {
						response.setContentType(MediaType.APPLICATION_JSON_VALUE);
						response.getWriter().write("{\"msg\":\"Login Success\"}");
					}
				});
	}

}
