package com.pranav.jwtauth.autoconfigure;

import com.pranav.jwtauth.repository.entity.TokenBlacklistEntry;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.boot.autoconfigure.AutoConfigurationPackages;
import org.springframework.boot.persistence.autoconfigure.EntityScanPackages;
import org.springframework.context.annotation.ImportBeanDefinitionRegistrar;
import org.springframework.core.type.AnnotationMetadata;

import java.util.ArrayList;
import java.util.List;

/**
 * Makes this library's {@code @Entity} classes visible to the consuming application's
 * {@code EntityManagerFactory}, which by default only scans the application's own
 * auto-configuration packages.
 *
 * <p>Registering {@link EntityScanPackages} is what {@code @EntityScan} does, but it cannot be used
 * naively from a library: {@code JpaBaseConfiguration.getPackagesToScan()} falls back to the
 * application's auto-configuration packages <em>only while that list is empty</em>. Registering just
 * this library's package would therefore stop the consuming application's own entities from being
 * scanned. So the application's packages are re-registered alongside ours - unless the application
 * declared its own {@code @EntityScan}, in which case that declaration is already present and is
 * left to stand on its own (ours merges into it).
 */
class AuthzEntityScanRegistrar implements ImportBeanDefinitionRegistrar, BeanFactoryAware {

    private BeanFactory beanFactory;

    @Override
    public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
        this.beanFactory = beanFactory;
    }

    @Override
    public void registerBeanDefinitions(AnnotationMetadata importingClassMetadata, BeanDefinitionRegistry registry) {
        List<String> packages = new ArrayList<>();
        packages.add(TokenBlacklistEntry.class.getPackageName());

        boolean applicationDeclaredEntityScan = registry.containsBeanDefinition(EntityScanPackages.class.getName());
        if (!applicationDeclaredEntityScan && AutoConfigurationPackages.has(this.beanFactory)) {
            packages.addAll(AutoConfigurationPackages.get(this.beanFactory));
        }

        EntityScanPackages.register(registry, packages);
    }
}
