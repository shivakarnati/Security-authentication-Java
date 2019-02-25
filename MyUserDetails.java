package com.lollie.web.engine.security;

import com.lollie.web.engine.db.entity.AppUser;
import com.lollie.web.engine.db.repository.AppUserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class MyUserDetails implements UserDetailsService {

    @Autowired
    private AppUserRepo appUserRepo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser user = appUserRepo.findByMobileNumber(username);

        if (user == null) {
            user = appUserRepo.findByEmailAddress(username);
        }


        if (user == null) {
            throw new UsernameNotFoundException(username + " not found");
        }
        System.out.println("UserInfo" + user.toString());

        return org.springframework.security.core.userdetails.User//
                .withUsername(username)//
                .password("")
                .authorities(user.getRole().toString())//
                .accountExpired(false)//
                .accountLocked(false)//
                .credentialsExpired(false)//
                .disabled(false)//
                .build();
    }

}
