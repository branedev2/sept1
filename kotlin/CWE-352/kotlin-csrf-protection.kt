import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.web.csrf.CookieCsrfTokenRepository
import org.springframework.security.web.csrf.CsrfTokenRepository
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository
import org.springframework.security.web.csrf.LazyCsrfTokenRepository
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository
import org.springframework.security.web.server.csrf.ServerCsrfTokenRepository
import org.springframework.security.web.server.csrf.WebSessionServerCsrfTokenRepository
import org.springframework.web.reactive.config.EnableWebFlux
import org.springframework.security.config.Customizer

// True Positives (Vulnerable Code)

@Configuration
@EnableWebSecurity
class bad_case_1 : WebSecurityConfigurerAdapter() {
// {fact rule=coral-csrf-rule@v1.0 defects=1}
    override fun configure(http: HttpSecurity) {
        // ruleid: kotlin-csrf-protection
        http.csrf().disable()
            .authorizeRequests()
            .anyRequest().authenticated()
            .and()
            .formLogin()
    }
// {/fact}
}

@Configuration
@EnableWebSecurity
class bad_case_2 : WebSecurityConfigurerAdapter() {
// {fact rule=coral-csrf-rule@v1.0 defects=1}
    override fun configure(http: HttpSecurity) {
        http.authorizeRequests()
            .anyRequest().authenticated()
            .and()
            .formLogin()
            .and()
            // ruleid: kotlin-csrf-protection
            .csrf().disable()
    }
// {/fact}
}

@Configuration
@EnableWebSecurity
class bad_case_3 {
// {fact rule=coral-csrf-rule@v1.0 defects=1}
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityWebFilterChain {
        // ruleid: kotlin-csrf-protection
        http.csrf { csrf -> csrf.disable() }
        http.authorizeRequests { auth -> auth.anyRequest().authenticated() }
        return http.build()
    }
// {/fact}
}

@Configuration
@EnableWebFlux
@EnableWebSecurity
class bad_case_4 {
// {fact rule=coral-csrf-rule@v1.0 defects=1}
    @Bean
    fun springSecurityFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
        // ruleid: kotlin-csrf-protection
        return http.csrf().disable()
            .authorizeExchange()
            .anyExchange().authenticated()
            .and()
            .build()
    }
// {/fact}
}

@Configuration
@EnableWebSecurity
class bad_case_5 {
// {fact rule=coral-csrf-rule@v1.0 defects=1}
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityWebFilterChain {
        http {
            authorizeRequests {
                authorize(anyRequest, authenticated)
            }
            // ruleid: kotlin-csrf-protection
            csrf { disable() }
        }
        return http.build()
    }
// {/fact}
}

@Configuration
@EnableWebSecurity
class bad_case_6 : WebSecurityConfigurerAdapter() {
// {fact rule=coral-csrf-rule@v1.0 defects=1}
    override fun configure(http: HttpSecurity) {
        http.headers().frameOptions().sameOrigin()
            // ruleid: kotlin-csrf-protection
            .and().csrf().disable()
            .authorizeRequests()
            .antMatchers("/api/**").permitAll()
            .anyRequest().authenticated()
    }
// {/fact}
}

@Configuration
@EnableWebSecurity
class bad_case_7 {
// {fact rule=coral-csrf-rule@v1.0 defects=1}
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityWebFilterChain {
        http.authorizeRequests().anyRequest().authenticated()
        // ruleid: kotlin-csrf-protection
        http.csrf { it.disable() }
        return http.build()
    }
// {/fact}
}

@Configuration
@EnableWebFlux
@EnableWebSecurity
class bad_case_8 {
// {fact rule=coral-csrf-rule@v1.0 defects=1}
    @Bean
    fun springSecurityFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
        return http
            .authorizeExchange().pathMatchers("/public/**").permitAll()
            .anyExchange().authenticated().and()
            // ruleid: kotlin-csrf-protection
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            .build()
    }
// {/fact}
}

@Configuration
@EnableWebSecurity
class bad_case_9 : WebSecurityConfigurerAdapter() {
// {fact rule=coral-csrf-rule@v1.0 defects=1}
    override fun configure(http: HttpSecurity) {
        // ruleid: kotlin-csrf-protection
        http.csrf().disable()
            .authorizeRequests()
            .antMatchers("/api/**").permitAll()
            .anyRequest().authenticated()
            .and()
            .httpBasic()
    }
// {/fact}
}

@Configuration
@EnableWebSecurity
class bad_case_10 {
// {fact rule=coral-csrf-rule@v1.0 defects=1}
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityWebFilterChain {
        // ruleid: kotlin-csrf-protection
        http.csrf().disable()
            .authorizeRequests { auth ->
                auth.antMatchers("/public/**").permitAll()
                auth.anyRequest().authenticated()
            }
        return http.build()
    }
// {/fact}
}

@Configuration
@EnableWebSecurity
class bad_case_11 : WebSecurityConfigurerAdapter() {
// {fact rule=coral-csrf-rule@v1.0 defects=1}
    override fun configure(http: HttpSecurity) {
        http.authorizeRequests()
            .antMatchers("/admin/**").hasRole("ADMIN")
            .antMatchers("/user/**").hasRole("USER")
            .anyRequest().authenticated()
            .and()
            .formLogin()
            .and()
            // ruleid: kotlin-csrf-protection
            .csrf().disable()
    }
// {/fact}
}

@Configuration
@EnableWebFlux
@EnableWebSecurity
class bad_case_12 {
// {fact rule=coral-csrf-rule@v1.0 defects=1}
    @Bean
    fun springSecurityFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
        http.authorizeExchange()
            .pathMatchers("/api/public/**").permitAll()
            .anyExchange().authenticated()
        
        // ruleid: kotlin-csrf-protection
        http.csrf().disable()
        
        return http.build()
    }
// {/fact}
}

@Configuration
@EnableWebSecurity
class bad_case_13 {
// {fact rule=coral-csrf-rule@v1.0 defects=1}
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityWebFilterChain {
        http {
            httpBasic { }
            formLogin { }
            // ruleid: kotlin-csrf-protection
            csrf { disable() }
            authorizeRequests {
                authorize("/api/**", permitAll)
                authorize(anyRequest, authenticated)
            }
        }
        return http.build()
    }
// {/fact}
}

@Configuration
@EnableWebSecurity
class bad_case_14 : WebSecurityConfigurerAdapter() {
// {fact rule=coral-csrf-rule@v1.0 defects=1}
    override fun configure(http: HttpSecurity) {
        http.sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            // ruleid: kotlin-csrf-protection
            .csrf().disable()
            .authorizeRequests()
            .anyRequest().authenticated()
    }
// {/fact}
}

@Configuration
@EnableWebSecurity
class bad_case_15 {
// {fact rule=coral-csrf-rule@v1.0 defects=1}
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityWebFilterChain {
        // ruleid: kotlin-csrf-protection
        http.csrf(Customizer.withDefaults()).csrf().disable()
            .authorizeRequests()
            .anyRequest().authenticated()
        return http.build()
    }
// {/fact}
}

// True Negatives (Secure Code)

@Configuration
@EnableWebSecurity
class good_case_1 : WebSecurityConfigurerAdapter() {
// {fact rule=coral-csrf-rule@v1.0 defects=0}
    override fun configure(http: HttpSecurity) {
        // ok: kotlin-csrf-protection
        http.csrf()
            .and()
            .authorizeRequests()
            .anyRequest().authenticated()
            .and()
            .formLogin()
    }
// {/fact}
}

@Configuration
@EnableWebSecurity
class good_case_2 : WebSecurityConfigurerAdapter() {
// {fact rule=coral-csrf-rule@v1.0 defects=0}
    override fun configure(http: HttpSecurity) {
        http.authorizeRequests()
            .anyRequest().authenticated()
            .and()
            .formLogin()
            .and()
            // ok: kotlin-csrf-protection
            .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
    }
// {/fact}
}

@Configuration
@EnableWebSecurity
class good_case_3 {
// {fact rule=coral-csrf-rule@v1.0 defects=0}
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityWebFilterChain {
        // ok: kotlin-csrf-protection
        http.csrf()
        http.authorizeRequests { auth -> auth.anyRequest().authenticated() }
        return http.build()
    }
// {/fact}
}

@Configuration
@EnableWebFlux
@EnableWebSecurity
class good_case_4 {
// {fact rule=coral-csrf-rule@v1.0 defects=0}
    @Bean
    fun springSecurityFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
        // ok: kotlin-csrf-protection
        return http.csrf()
            .csrfTokenRepository(WebSessionServerCsrfTokenRepository())
            .and()
            .authorizeExchange()
            .anyExchange().authenticated()
            .and()
            .build()
    }
// {/fact}
}

@Configuration
@EnableWebSecurity
class good_case_5 {
    @Bean
    fun csrfTokenRepository(): CsrfTokenRepository {
        return HttpSessionCsrfTokenRepository()
    }
    
// {fact rule=coral-csrf-rule@v1.0 defects=0}
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityWebFilterChain {
        http {
            authorizeRequests {
                authorize(anyRequest, authenticated)
            }
            // ok: kotlin-csrf-protection
            csrf { csrfTokenRepository(csrfTokenRepository()) }
        }
        return http.build()
    }
// {/fact}
}

@Configuration
@EnableWebSecurity
class good_case_6 : WebSecurityConfigurerAdapter() {
// {fact rule=coral-csrf-rule@v1.0 defects=0}
    override fun configure(http: HttpSecurity) {
        http.headers().frameOptions().sameOrigin()
            // ok: kotlin-csrf-protection
            .and().csrf()
            .authorizeRequests()
            .antMatchers("/api/**").permitAll()
            .anyRequest().authenticated()
    }
// {/fact}
}

@Configuration
@EnableWebSecurity
class good_case_7 {
// {fact rule=coral-csrf-rule@v1.0 defects=0}
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityWebFilterChain {
        http.authorizeRequests().anyRequest().authenticated()
        // ok: kotlin-csrf-protection
        http.csrf { it.csrfTokenRepository(LazyCsrfTokenRepository(HttpSessionCsrfTokenRepository())) }
        return http.build()
    }
// {/fact}
}

@Configuration
@EnableWebFlux
@EnableWebSecurity
class good_case_8 {
    @Bean
    fun csrfTokenRepository(): ServerCsrfTokenRepository {
        return CookieServerCsrfTokenRepository.withHttpOnlyFalse()
    }
    
// {fact rule=coral-csrf-rule@v1.0 defects=0}
    @Bean
    fun springSecurityFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
        return http
            .authorizeExchange().pathMatchers("/public/**").permitAll()
            .anyExchange().authenticated().and()
            // ok: kotlin-csrf-protection
            .csrf().csrfTokenRepository(csrfTokenRepository()).and()
            .build()
    }
// {/fact}
}

@Configuration
@EnableWebSecurity
class good_case_9 : WebSecurityConfigurerAdapter() {
// {fact rule=coral-csrf-rule@v1.0 defects=0}
    override fun configure(http: HttpSecurity) {
        // ok: kotlin-csrf-protection
        http.csrf()
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            .and()
            .authorizeRequests()
            .antMatchers("/api/**").permitAll()
            .anyRequest().authenticated()
            .and()
            .httpBasic()
    }
// {/fact}
}

@Configuration
@EnableWebSecurity
class good_case_10 {
// {fact rule=coral-csrf-rule@v1.0 defects=0}
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityWebFilterChain {
        // ok: kotlin-csrf-protection
        http.csrf()
            .authorizeRequests { auth ->
                auth.antMatchers("/public/**").permitAll()
                auth.anyRequest().authenticated()
            }
        return http.build()
    }
// {/fact}
}

@Configuration
@EnableWebSecurity
class good_case_11 : WebSecurityConfigurerAdapter() {
// {fact rule=coral-csrf-rule@v1.0 defects=0}
    override fun configure(http: HttpSecurity) {
        http.authorizeRequests()
            .antMatchers("/admin/**").hasRole("ADMIN")
            .antMatchers("/user/**").hasRole("USER")
            .anyRequest().authenticated()
            .and()
            .formLogin()
            .and()
            // ok: kotlin-csrf-protection
            .csrf()
    }
// {/fact}
}

@Configuration
@EnableWebFlux
@EnableWebSecurity
class good_case_12 {
// {fact rule=coral-csrf-rule@v1.0 defects=0}
    @Bean
    fun springSecurityFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
        http.authorizeExchange()
            .pathMatchers("/api/public/**").permitAll()
            .anyExchange().authenticated()
        
        // ok: kotlin-csrf-protection
        http.csrf()
        
        return http.build()
    }
// {/fact}
}

@Configuration
@EnableWebSecurity
class good_case_13 {
// {fact rule=coral-csrf-rule@v1.0 defects=0}
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityWebFilterChain {
        http {
            httpBasic { }
            formLogin { }
            // ok: kotlin-csrf-protection
            csrf { }
            authorizeRequests {
                authorize("/api/**", permitAll)
                authorize(anyRequest, authenticated)
            }
        }
        return http.build()
    }
// {/fact}
}

@Configuration
@EnableWebSecurity
class good_case_14 : WebSecurityConfigurerAdapter() {
// {fact rule=coral-csrf-rule@v1.0 defects=0}
    override fun configure(http: HttpSecurity) {
        http.sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            // ok: kotlin-csrf-protection
            .csrf()
            .authorizeRequests()
            .anyRequest().authenticated()
    }
// {/fact}
}

@Configuration
@EnableWebSecurity
class good_case_15 {
// {fact rule=coral-csrf-rule@v1.0 defects=0}
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityWebFilterChain {
        // ok: kotlin-csrf-protection
        http.csrf(Customizer.withDefaults())
            .authorizeRequests()
            .anyRequest().authenticated()
        return http.build()
    }
// {/fact}
}