package com.xdv.client.wallet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.AsyncConfigurerSupport;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;


@SpringBootApplication()
@EnableAsync()
public class WalletApplication extends AsyncConfigurerSupport {
	private static Logger LOG = LoggerFactory.getLogger(WalletApplication.class);

	public static void main(String[] args) {
		SpringApplication.run(WalletApplication.class, args);
	}



	@Override
	public Executor getAsyncExecutor() {
		ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
		executor.setCorePoolSize(2);
		executor.setMaxPoolSize(2);
		executor.setQueueCapacity(500);
		executor.setThreadNamePrefix("main.accounts:");
		executor.initialize();
		return executor;
	}


}