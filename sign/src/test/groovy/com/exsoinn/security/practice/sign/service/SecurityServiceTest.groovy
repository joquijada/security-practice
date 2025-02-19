package com.exsoinn.security.practice.sign.service

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.test.context.ContextConfiguration
import spock.lang.Specification


@SpringBootTest
@ContextConfiguration
class SecurityServiceTest extends Specification {
    @Autowired
    SecurityService signService

    def "request token"() {
        when:
        def signature = signService.requestToken()

        then:
        println signature
        signature != null
    }
}
