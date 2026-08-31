package com.ahmetkaragunlu.guidematebackend.demo.config;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Profile;
import org.springframework.core.Ordered;
import org.springframework.core.PriorityOrdered;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

@Component
@Profile(DemoTargetSafetyPolicy.DEMO_PROFILE)
public class DemoEnvironmentGuard implements BeanFactoryPostProcessor, EnvironmentAware, PriorityOrdered {

    private Environment environment;

    @Override
    public void setEnvironment(Environment environment) {
        this.environment = environment;
    }

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
        if (environment == null) {
            throw new IllegalStateException("Demo environment is unavailable");
        }
        DemoTargetSafetyPolicy.requireSafeTargets(
                environment.getActiveProfiles(),
                environment.getRequiredProperty("spring.datasource.url"),
                environment.getRequiredProperty("media.storage-root")
        );
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
