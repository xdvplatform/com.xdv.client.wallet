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
public class WalletApplication extends AsyncConfigurerSupport {
	private static Logger LOG = LoggerFactory.getLogger(WalletApplication.class);

	public static void main(String[] args) {
		SpringApplication.run(WalletApplication.class, args);
	}



}