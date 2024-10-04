package com.example.userservice1.Controllers;

import com.example.userservice1.Exceptions.InvalidPasswordException;
import com.example.userservice1.Exceptions.InvalidTokenException;
import com.example.userservice1.Models.Token;
import com.example.userservice1.Models.User;
import com.example.userservice1.Services.UserService1;
import com.example.userservice1.dtos.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/users")
public class UserController {

    @Autowired
    private UserService1 userService;


    @PostMapping("/signup")  //localhost:8080/users/signup
    public UserDto signUp(@RequestBody SignUpRequestDto requestDto){
        User user = userService.signUp(requestDto.getEmail(), requestDto.getPassword(), requestDto.getName());

        return fromUser(user);
    }

    @PostMapping("/login")
    public LoginResponseDto logIn(@RequestBody LoginRequestDto requestDto) throws InvalidPasswordException {
        Token token = userService.login(requestDto.getEmail(), requestDto.getPassword());

        return fromToken(token);
    }

    public LoginResponseDto fromToken(Token token) {
        LoginResponseDto dto = new LoginResponseDto();
        dto.setToken(token);
        return dto;
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logOut(@RequestBody LogOutRequestDto requestDto){
        ResponseEntity<Void> responseEntity = null;
        try {
            userService.logOut(requestDto.getToken());
            responseEntity = new ResponseEntity<>(HttpStatus.OK);
        } catch (Exception e) {
            System.out.println("Sorry Somethings went wrong");
            responseEntity = new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
        return responseEntity;
    }

    @PostMapping("validate/{tokenValue}")
    public UserDto validateToken(@PathVariable String tokenValue) throws InvalidTokenException {
        return fromUser(userService.validateToken(tokenValue));
    }

    public static UserDto fromUser(User user) {
        UserDto userDto = new UserDto();
        userDto.setName(user.getName());
        userDto.setEmail(user.getEmail());
        userDto.setEmailVerified(user.isEmailVerified());
        userDto.setRoles(user.getRoles());

        return userDto;
    }
}
