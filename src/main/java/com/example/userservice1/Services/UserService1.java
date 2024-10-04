package com.example.userservice1.Services;

import com.example.userservice1.Exceptions.InvalidPasswordException;
import com.example.userservice1.Exceptions.InvalidTokenException;
import com.example.userservice1.Models.Role;
import com.example.userservice1.Models.Token;
import com.example.userservice1.Models.User;
import com.example.userservice1.Repositories.RoleRepository;
import com.example.userservice1.Repositories.TokenRepository;
import com.example.userservice1.Repositories.UserRepository;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.ZoneId;
import java.util.*;

@Service
public class UserService1 {
    private RoleRepository roleRepository;
    private UserRepository userRepository;
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    private TokenRepository tokenRepository;



    public UserService1(TokenRepository tokenRepository,
                        UserRepository userRepository,
                        BCryptPasswordEncoder bCryptPasswordEncoder,
                        RoleRepository roleRepository) {
        this.tokenRepository = tokenRepository;
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.roleRepository = roleRepository;
    }

    public User signUp(String email, String password, String name) {
        Optional<User> optionalUser = userRepository.findByEmail(email);

        if (optionalUser .isPresent()) {
            //user is already present in DB, so no need to signUp
            return optionalUser .get();
        }

        List<Long> roleIds = Arrays.asList(1L, 2L, 3L,4L);
        List<Role> roles = roleRepository.findAllById(roleIds);



        User user = new User();
        user.setEmail(email);
        user.setName(name);
        user.setEmailVerified(true);
        user.setRoles(roles);
        user.setHashedPassword(bCryptPasswordEncoder.encode(password));

        return userRepository.save(user);
    }

    public Token login(String email, String password) throws InvalidPasswordException {
        /*
        * 1.Check if user exists with given email id
        * 2.if not throw exception or return the user to login page
        * 3.if yes , then compare the password with the password stored in DB
        * 4.if password matches then login is successful and return new token
        *
        * */
        Optional<User> optionalUser = userRepository.findByEmail(email);

        if (optionalUser.isEmpty()) {
            //it is meaning that this particular user is not present in the db
            return null;
        }

        User user = optionalUser.get();

        if (user.isDeleted()) {
            return null;
        }

        if (!user.isEmailVerified()) {
            return null;
        }

        if (!bCryptPasswordEncoder.matches(password, user.getHashedPassword())) {
            throw new InvalidPasswordException("Please Enter the correct Password");
        }

        // now login is successful, system should generate a new ticket
        Token token = generateToken(user);
        Token savedToken = tokenRepository.save(token);

        return savedToken;
    }

    private Token generateToken(User user) {
        //Here we are setting the expiry date for our token
        LocalDate currentTime = LocalDate.now();
        LocalDate thirtyDaysFromCurrentTime = currentTime.plusDays(30);

        Date expiryDate = Date.from(thirtyDaysFromCurrentTime.atStartOfDay(ZoneId.systemDefault()).toInstant());

        Token token = new Token();
        token.setExpiryAt(expiryDate);

        //so basically token value is a randomly generated string of 128 characters --- > standard
        token.setValue(RandomStringUtils.randomAlphanumeric(128));
        token.setUser(user);
        return token;
    }

    public void logOut(String tokenValue) throws InvalidTokenException {
        //first we should check the given token is valid or not and also we need to check is_deleted == false
        Optional<Token> optionalToken = tokenRepository.findByValueAndIsDeleted(tokenValue,false);

        if (optionalToken.isEmpty()) {
            //Throw an exception
            throw new InvalidTokenException("Invalid Token Passed");
        }

        Token token = optionalToken.get();
        token.setDeleted(true);
        tokenRepository.save(token);
        return;
    }

    public User validateToken(String tokenValue) throws InvalidTokenException {
        Optional<Token> optionalToken = tokenRepository.findByValueAndIsDeleted(tokenValue,false);

        if (optionalToken.isEmpty()) {
            throw new InvalidTokenException("Invalid Token Passed");
        }

        return optionalToken.get().getUser();
    }
}
