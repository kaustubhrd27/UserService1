package com.example.userservice1.security.Exceptions;

public class UserIdNotFoundException extends Exception{
    public UserIdNotFoundException(String message){
        super(message);
    }
}
