package com.scb.loanapi.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.circuitbreaker.EnableCircuitBreaker;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
@EnableEurekaClient
@EnableZuulProxy
@EnableCircuitBreaker
public class LoanManagementApiGatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(LoanManagementApiGatewayApplication.class, args);
	}

	@Bean
	  public SimpleZuulFilter simpleFilter() {
	    return new SimpleZuulFilter();
	  }
}
