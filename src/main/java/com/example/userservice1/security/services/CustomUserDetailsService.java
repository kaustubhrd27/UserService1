package com.example.userservice1.security.services;

import com.example.userservice1.Models.User;
import com.example.userservice1.Repositories.UserRepository;
import com.example.userservice1.security.Exceptions.EmailIdNotVerifiedException;
import com.example.userservice1.security.Exceptions.UserIdNotFoundException;
import com.example.userservice1.security.Models.CustomUserDetails;
import lombok.SneakyThrows;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @SneakyThrows
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // get the user with the given username from DB
        Optional<User> optionalUser = userRepository.findByEmail(username);

        if (optionalUser.isEmpty()) {
            throw new UsernameNotFoundException("user with username/email" + username + " not found");
        }

        User user = optionalUser.get();

        if(user.isDeleted()) {
            throw new UserIdNotFoundException("user with username/email" + username + " is deleted");
        }

        if(!user.isEmailVerified()) {
            throw new EmailIdNotVerifiedException("This Email Id Isn't Verified");
        }

        CustomUserDetails customUserDetails = new CustomUserDetails(user);

        return customUserDetails;
    }
}
