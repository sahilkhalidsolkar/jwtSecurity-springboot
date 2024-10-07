### **JWT Authentication with Spring Security: A Step-by-Step Guide**

In this tutorial, we will explore JWT authentication using Spring Security. We'll break down the theoretical flow of how Spring Security works with JWT and explain each class and its role in the authentication process.

---

### **Table of Contents**

1. **Understanding Spring Security and JWT Flow**
2. **Project Structure Overview**
3. **Detailed Explanation of Each Class**
    - `JwtPracticeSecurityApplication.java`
    - `CustomUserDetailsService.java`
    - `JwtAuthenticationEntrypoint.java`
    - `JwtAuthenticationFilter.java`
    - `JwtTokenProvider.java`
    - `SecurityConfig.java`
    - `AuthController.java`
    - `SimpleController.java`
    - `User.java` and `Role.java`
    - `AuthService.java`
    - `Repositories`

---

### **1. Understanding Spring Security and JWT Flow**

Before diving into the code, let’s first understand the typical flow for JWT authentication in a Spring Boot application:

1. **User Requests Access**: The user sends a request with their login credentials (username and password) to the server.
2. **Authentication Manager Validates Credentials**: The `AuthenticationManager` is used to verify these credentials using the `UserDetailsService`.
3. **Token Generation**: If the credentials are correct, a JWT token is generated using a secret key. This token is then returned to the client.
4. **Client Stores Token**: The client stores the token, typically in local storage or cookies, and attaches it to the Authorization header (as a "Bearer" token) in subsequent requests.
5. **Token Validation**: For every request after login, the server validates the token. If valid, the request is processed, and user-specific data is provided.
6. **Accessing Protected Resources**: Based on roles and authorities in the JWT, the user can access protected resources.

### **2. Project Structure Overview**

Here’s the overview of the main classes used in this project:

- **JwtPracticeSecurityApplication.java**: The main application class to bootstrap the Spring Boot application.
- **CustomUserDetailsService.java**: Loads user-specific data from the database for authentication.
- **JwtAuthenticationEntrypoint.java**: Handles unauthorized access attempts.
- **JwtAuthenticationFilter.java**: Intercepts requests, validates JWT, and sets the security context.
- **JwtTokenProvider.java**: Generates and validates JWT tokens.
- **SecurityConfig.java**: Configures Spring Security, including the JWT filters.
- **AuthController.java**: Handles login requests and returns a JWT token upon successful authentication.
- **SimpleController.java**: A controller that demonstrates role-based authorization.
- **AuthService.java**: Service to handle authentication logic.
- **User.java** and **Role.java**: Entity classes representing users and their roles.
- **Repositories**: `UserRepository` and `RoleRepository` for database interaction.

---

### **3. Detailed Explanation of Each Class**

#### **3.1 JwtPracticeSecurityApplication.java**

This is the main class of the Spring Boot application, responsible for launching the application.

```java
@SpringBootApplication
public class JwtPracticeSecurityApplication {
    public static void main(String[] args) {
        SpringApplication.run(JwtPracticeSecurityApplication.class, args);
    }
}
```

#### **3.2 CustomUserDetailsService.java**

- **Purpose**: Implements `UserDetailsService` to load user-specific data from the database.
- **Explanation**: This service is used by Spring Security to authenticate the user based on the provided credentials. We retrieve the user from the database and convert their roles into `SimpleGrantedAuthority`.

```java
@Override
public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    User user = userRepository.findByUsername(username)
        .orElseThrow(() -> new UsernameNotFoundException("User not exists by user name"));
    Set<SimpleGrantedAuthority> authorities = user.getRoles()
        .stream()
        .map(role -> new SimpleGrantedAuthority(role.getName()))
        .collect(Collectors.toSet());

    return new org.springframework.security.core.userdetails.User(
            username,
            user.getPassword(),
            authorities
    );
}
```

#### **3.3 JwtAuthenticationEntrypoint.java**

- **Purpose**: Handles unauthorized requests by sending a 401 error.
- **Explanation**: Whenever a user tries to access a secured endpoint without being authenticated, this entry point gets triggered.

```java
@Override
public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage());
}
```

#### **3.4 JwtAuthenticationFilter.java**

- **Purpose**: This filter intercepts every request, extracts the JWT from the `Authorization` header, and validates it.
- **Explanation**: If the token is valid, the filter sets the authentication in the `SecurityContextHolder`, allowing the user to access protected resources.

```java
@Override
protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
    String token = getTokenFromRequest(request);
    if (StringUtils.hasText(token) && jwtTokenProvider.validateToken(token)) {
        String username = jwtTokenProvider.getUsername(token);
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());
        authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
    }
    filterChain.doFilter(request, response);
}
```

#### **3.5 JwtTokenProvider.java**

- **Purpose**: This class is responsible for generating and validating JWT tokens.
- **Explanation**: It creates a token using the `username` and signs it with a secret key. It also contains methods to extract user details from the token and validate the token.

```java
public String generateToken(Authentication authentication) {
    String username = authentication.getName();
    Date currentDate = new Date();
    Date expireDate = new Date(currentDate.getTime() + jwtExpirationDate);
    return Jwts.builder()
            .subject(username)
            .issuedAt(new Date())
            .expiration(expireDate)
            .signWith(key(), SignatureAlgorithm.HS256)
            .compact();
}

public boolean validateToken(String token) {
    Jwts.parserBuilder().setSigningKey(key()).build().parseClaimsJws(token);
    return true;
}
```

#### **3.6 SecurityConfig.java**

- **Purpose**: Configures Spring Security, sets up JWT filter, and defines security rules.
- **Explanation**: This configuration disables CSRF protection (since we're using JWT), allows anonymous access to `/api/auth/**`, and requires authentication for any other endpoint. It also registers the JWT filter.

```java
httpSecurity.csrf(AbstractHttpConfigurer::disable)
    .authorizeHttpRequests(authorize -> {
        authorize.requestMatchers("/api/auth/**").permitAll();
        authorize.anyRequest().authenticated();
    })
    .httpBasic(Customizer.withDefaults());

httpSecurity.addFilterBefore(authenticationFilter, UsernamePasswordAuthenticationFilter.class);
```

#### **3.7 AuthController.java**

- **Purpose**: Handles login requests and returns the JWT token.
- **Explanation**: The controller receives login credentials, delegates authentication to the `AuthService`, and returns the generated JWT token to the client.

```java
@PostMapping("/login")
public ResponseEntity<AuthResponseDto> login(@RequestBody LoginDto loginDto) {
    String token = authService.login(loginDto);
    AuthResponseDto authResponseDto = new AuthResponseDto();
    authResponseDto.setAccessToken(token);
    return new ResponseEntity<>(authResponseDto, HttpStatus.OK);
}
```

#### **3.8 SimpleController.java**

- **Purpose**: A simple controller demonstrating role-based access control.
- **Explanation**: This controller contains two endpoints, `/admin` and `/user`, which can only be accessed by users with the appropriate roles (`ADMIN` and `USER`, respectively).

```java
@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/admin")
public ResponseEntity<String> helloAdmin() {
    return ResponseEntity.ok("Hello Admin");
}

@PreAuthorize("hasRole('USER')")
@GetMapping("/user")
public ResponseEntity<String> helloUser() {
    return ResponseEntity.ok("Hello User");
}
```

#### **3.9 User and Role Model**

- **Purpose**: Represents the `User` and `Role` entities in the database.
- **Explanation**: The `User` entity stores user information, and each user can have multiple roles. The roles are stored in a `Set<Role>`, and there is a many-to-many relationship between users and roles.

```java
@ManyToMany(fetch = FetchType.EAGER)
@JoinTable(name = "users_roles",
        joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id"),
        inverseJoinColumns = @JoinColumn(name = "role_id", referencedColumnName = "id")
)
private Set<Role> roles;
```

#### **3.10 AuthService.java**

- **Purpose**: Handles the login logic and token generation.
- **Explanation**: The service authenticates the user, sets the security context, and then generates a JWT token.

```java
public String login(LoginDto loginDto) {
    Authentication authentication = authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
            loginDto.getUsername(), loginDto.getPassword()
        )
    );
    SecurityContextHolder.getContext().setAuthentication(authentication);
    return jwtTokenProvider.generateToken(authentication);
}
```

---

### **Conclusion**

In this tutorial, we have covered the complete setup for implementing JWT authentication in a Spring

Boot application. Each class plays a crucial role in the overall flow of authentication and authorization. You can further extend this setup by adding refresh tokens, improving error handling, and enhancing security practices.