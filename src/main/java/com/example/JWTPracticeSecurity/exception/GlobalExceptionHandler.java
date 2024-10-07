package com.example.JWTPracticeSecurity.exception;

import io.jsonwebtoken.JwtException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import javax.security.sasl.AuthenticationException;

@ControllerAdvice
public class GlobalExceptionHandler {

//    @ExceptionHandler(AuthenticationException.class)
//    public ResponseEntity<String> handleAuthenticationException(AuthenticationException ex) {
//        return new ResponseEntity<>(ex.getMessage(), HttpStatus.UNAUTHORIZED);
//    }
//    @ExceptionHandler(UsernameNotFoundException.class)
//    public ResponseEntity<String> handleUsernameNotFoundException(UsernameNotFoundException ex) {
//        return new ResponseEntity<>(ex.getMessage(), HttpStatus.UNAUTHORIZED);
//    }
//
//    @ExceptionHandler(AccessDeniedException.class)
//    public ResponseEntity<String> handleAccessDeniedException(AccessDeniedException ex) {
//        return new ResponseEntity<>("You do not have permission to access this resource", HttpStatus.FORBIDDEN);
//    }
//
//    @ExceptionHandler(JwtException.class)
//    public ResponseEntity<String> handleJwtException(JwtException ex) {
//        return new ResponseEntity<>("Invalid or expired JWT token", HttpStatus.UNAUTHORIZED);
//    }
//
//    @ExceptionHandler(InsufficientAuthenticationException.class)
//    public ResponseEntity<String> handleInsufficientAuthenticationException(InsufficientAuthenticationException ex) {
//        return new ResponseEntity<>("Authentication is required to access this resource", HttpStatus.FORBIDDEN);
//    }
//
//    @ExceptionHandler(SessionAuthenticationException.class)
//    public ResponseEntity<String> handleSessionAuthenticationException(SessionAuthenticationException ex) {
//        return new ResponseEntity<>("Session error: " + ex.getMessage(), HttpStatus.UNAUTHORIZED);
//    }
//
//    @ExceptionHandler(InternalAuthenticationServiceException.class)
//    public ResponseEntity<String> handleInternalAuthenticationServiceException(InternalAuthenticationServiceException ex) {
//        return new ResponseEntity<>("Internal authentication service error", HttpStatus.INTERNAL_SERVER_ERROR);
//    }
//
//    @ExceptionHandler(AuthenticationCredentialsNotFoundException.class)
//    public ResponseEntity<String> handleAuthenticationCredentialsNotFoundException(AuthenticationCredentialsNotFoundException ex) {
//        return new ResponseEntity<>("Authentication credentials not found", HttpStatus.UNAUTHORIZED);
//    }
}
