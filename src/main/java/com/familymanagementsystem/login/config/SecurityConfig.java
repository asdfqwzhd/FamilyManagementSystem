package com.familymanagementsystem.login.config;

import java.io.PrintWriter;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
//		http.cors().and().csrf().disable();
//		http.csrf().disable();
		http.authorizeRequests().withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
			@Override
			public <O extends FilterSecurityInterceptor> O postProcess(O object) {
//                object.setAccessDecisionManager(customUrlDecisionManager);
//                object.setSecurityMetadataSource(customFilterInvocationSecurityMetadataSource);
				return object;
			}
		}).and().logout().logoutSuccessHandler((req, resp, authentication) -> {
			resp.setContentType("application/json;charset=utf-8");
			PrintWriter out = resp.getWriter();
//            out.write(new ObjectMapper().writeValueAsString(RespBean.ok("注销成功!")));
			out.flush();
			out.close();
		}).permitAll()
		// .anyRequest().authenticated()// 所有请求必须认证过才能访问[没有配置MyFilter，DecisionManager之前]
//				.and().formLogin().usernameParameter("username").passwordParameter("password")
//				// 真正的登录接口，必须是key-value形式
//				.loginProcessingUrl("/login").successHandler(new AuthenticationSuccessHandler() {
//					@Override
//					public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
//							Authentication authentication) throws IOException, ServletException {
//						response.setContentType(MediaType.APPLICATION_JSON_VALUE);
//						response.getWriter().write("{\"msg\":\"Login Success\"}");
//					}
//				})
				.and().csrf().disable().exceptionHandling()
				// 没有认证时，在这里处理结果，不要重定向
				.authenticationEntryPoint((req, resp, authException) -> {
					resp.setContentType("application/json;charset=utf-8");
					resp.setStatus(401);
					PrintWriter out = resp.getWriter();
//                            RespBean respBean = RespBean.error("访问失败!");
//                            if (authException instanceof InsufficientAuthenticationException) {
//                                respBean.setMsg("请求失败，请联系管理员!");
//                            }
//                            out.write(new ObjectMapper().writeValueAsString(respBean));
					out.flush();
					out.close();
				});
		http.addFilterAt(loginFilter(), UsernamePasswordAuthenticationFilter.class);
	}

//	@Bean
//	public WebMvcConfigurer corsConfigurer1() {
//		return new WebMvcConfigurer() {
//			@Override
//			public void addCorsMappings(CorsRegistry registry) {
//				registry.addMapping("/**");
//			}
//		};
//
//	}
//
//	@Bean
//	public FilterRegistrationBean<CorsFilter> corsConfigurer() {
//		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//		org.springframework.web.cors.CorsConfiguration config = new org.springframework.web.cors.CorsConfiguration();
//		config.setAllowCredentials(true);
//		// 设置你要允许的网站域名，如果全允许则设为 *
//		config.addAllowedOrigin("*");
//		// 如果要限制 HEADER 或 METHOD 请自行更改
//		config.addAllowedHeader("*");
//		config.addAllowedMethod("*");
//		source.registerCorsConfiguration("/**", config);
//		FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<CorsFilter>(new CorsFilter(source));
//		// 这个顺序很重要哦，为避免麻烦请设置在最前
//		bean.setOrder(0);
//		return bean;
//	}

	@Bean
	LoginFilter loginFilter() throws Exception {
		LoginFilter loginFilter = new LoginFilter();
		loginFilter.setAuthenticationSuccessHandler((request, response, authentication) -> {
			response.setContentType("application/json;charset=utf-8");
			PrintWriter out = response.getWriter();
//			Hr hr = (Hr) authentication.getPrincipal();
//			hr.setPassword(null);
//			RespBean ok = RespBean.ok("登录成功!", hr);
//			String s = new ObjectMapper().writeValueAsString(ok);
//			out.write(s);
			out.flush();
			out.close();
		});
		loginFilter.setAuthenticationFailureHandler((request, response, exception) -> {
			response.setContentType("application/json;charset=utf-8");
			PrintWriter out = response.getWriter();
			response.setStatus(500);
//			RespBean respBean = RespBean.error(exception.getMessage());
//			if (exception instanceof LockedException) {
//				respBean.setMsg("账户被锁定，请联系管理员!");
//			} else if (exception instanceof CredentialsExpiredException) {
//				respBean.setMsg("密码过期，请联系管理员!");
//			} else if (exception instanceof AccountExpiredException) {
//				respBean.setMsg("账户过期，请联系管理员!");
//			} else if (exception instanceof DisabledException) {
//				respBean.setMsg("账户被禁用，请联系管理员!");
//			} else if (exception instanceof BadCredentialsException) {
//				respBean.setMsg("用户名或者密码输入错误，请重新输入!");
//			}
//			out.write(new ObjectMapper().writeValueAsString(respBean));
			out.flush();
			out.close();
		});
		loginFilter.setAuthenticationManager(authenticationManagerBean());
		loginFilter.setFilterProcessesUrl("/login");
//        ConcurrentSessionControlAuthenticationStrategy sessionStrategy = new ConcurrentSessionControlAuthenticationStrategy(sessionRegistry());
//        sessionStrategy.setMaximumSessions(1);
//        loginFilter.setSessionAuthenticationStrategy(sessionStrategy);
		return loginFilter;
	}

}
