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
//            out.write(new ObjectMapper().writeValueAsString(RespBean.ok("ע���ɹ�!")));
			out.flush();
			out.close();
		}).permitAll()
		// .anyRequest().authenticated()// �������������֤�����ܷ���[û������MyFilter��DecisionManager֮ǰ]
//				.and().formLogin().usernameParameter("username").passwordParameter("password")
//				// �����ĵ�¼�ӿڣ�������key-value��ʽ
//				.loginProcessingUrl("/login").successHandler(new AuthenticationSuccessHandler() {
//					@Override
//					public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
//							Authentication authentication) throws IOException, ServletException {
//						response.setContentType(MediaType.APPLICATION_JSON_VALUE);
//						response.getWriter().write("{\"msg\":\"Login Success\"}");
//					}
//				})
				.and().csrf().disable().exceptionHandling()
				// û����֤ʱ�������ﴦ��������Ҫ�ض���
				.authenticationEntryPoint((req, resp, authException) -> {
					resp.setContentType("application/json;charset=utf-8");
					resp.setStatus(401);
					PrintWriter out = resp.getWriter();
//                            RespBean respBean = RespBean.error("����ʧ��!");
//                            if (authException instanceof InsufficientAuthenticationException) {
//                                respBean.setMsg("����ʧ�ܣ�����ϵ����Ա!");
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
//		// ������Ҫ�������վ���������ȫ��������Ϊ *
//		config.addAllowedOrigin("*");
//		// ���Ҫ���� HEADER �� METHOD �����и���
//		config.addAllowedHeader("*");
//		config.addAllowedMethod("*");
//		source.registerCorsConfiguration("/**", config);
//		FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<CorsFilter>(new CorsFilter(source));
//		// ���˳�����ҪŶ��Ϊ�����鷳����������ǰ
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
//			RespBean ok = RespBean.ok("��¼�ɹ�!", hr);
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
//				respBean.setMsg("�˻�������������ϵ����Ա!");
//			} else if (exception instanceof CredentialsExpiredException) {
//				respBean.setMsg("������ڣ�����ϵ����Ա!");
//			} else if (exception instanceof AccountExpiredException) {
//				respBean.setMsg("�˻����ڣ�����ϵ����Ա!");
//			} else if (exception instanceof DisabledException) {
//				respBean.setMsg("�˻������ã�����ϵ����Ա!");
//			} else if (exception instanceof BadCredentialsException) {
//				respBean.setMsg("�û����������������������������!");
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
