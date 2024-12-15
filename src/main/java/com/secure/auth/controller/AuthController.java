package com.secure.auth.controller;

import com.secure.auth.model.User;
import com.secure.auth.repository.UserRepository;
import com.secure.auth.util.PasswordHasher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private UserRepository userRepository;

    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@RequestBody User user) {
        if (userRepository.findByUsername(user.getUsername()).isPresent()) {
            return ResponseEntity.badRequest().body("Username already exists");
        }
        user.setPassword(PasswordHasher.hashPassword(user.getPassword()));
        userRepository.save(user);
        return ResponseEntity.ok("User registered successfully");
    }
}

@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody User user) {
    User existingUser = userRepository.findByUsername(user.getUsername())
            .orElseThrow(() -> new RuntimeException("Invalid username or password"));

    if (!PasswordHasher.verifyPassword(user.getPassword(), existingUser.getPassword())) {
        return ResponseEntity.status(401).body("Invalid credentials");
    }

    String token = JwtUtil.generateToken(user.getUsername());
    return ResponseEntity.ok(token);
}
