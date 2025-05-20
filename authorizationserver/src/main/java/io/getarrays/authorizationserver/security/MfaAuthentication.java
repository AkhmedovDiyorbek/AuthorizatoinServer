package io.getarrays.authorizationserver.security;

import lombok.Getter;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Collection;

import static org.springframework.security.core.authority.AuthorityUtils.createAuthorityList;

@Getter
public class MfaAuthentication extends AnonymousAuthenticationToken {
    private final Authentication primaryAuthentication;

    public MfaAuthentication(Authentication authentication, String authority) {
        super("anonymous", "principal", createAuthorityList("ROLE_ANONYMOUS", authority));
        this.primaryAuthentication = authentication;
    }

    @Override
    public Object getPrincipal() {
        return this.primaryAuthentication;
    }
}
