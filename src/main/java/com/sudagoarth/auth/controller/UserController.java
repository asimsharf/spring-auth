package com.sudagoarth.auth.controller;

import com.sudagoarth.auth.entity.ApiResponse;
import com.sudagoarth.auth.entity.ApiResponseWithToken;
import com.sudagoarth.auth.entity.AuthRequest;
import com.sudagoarth.auth.JwtService;
import com.sudagoarth.auth.entity.UserInfo;
import com.sudagoarth.auth.service.UserInfoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class UserController {

    @Autowired
    private UserInfoService service;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @GetMapping("/welcome")
    public ApiResponse welcome() {
        return new ApiResponse(true, "Welcome to the API", null);
    }

    @PostMapping("/addNewUser")
    public ApiResponse addNewUser(@RequestBody UserInfo userInfo) {
        if (service.addUser(userInfo)) {
            return new ApiResponse(true, "User added successfully", null);
        } else {
            return new ApiResponse(false, "User already exists", null);
        }
    }

    @GetMapping("/user/userProfile")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public ApiResponse userProfile() {
        return new ApiResponse(true, "Welcome to User Profile", null);
    }

    @GetMapping("/admin/adminProfile")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ApiResponse adminProfile() {
        return new ApiResponse(true, "Welcome to Admin Profile", null);
    }

    @PostMapping("/generateToken")
    public ApiResponseWithToken authenticateAndGetToken(@RequestBody AuthRequest authRequest) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.username(), authRequest.password()));
        if (authentication.isAuthenticated()) {
            return new ApiResponseWithToken(true, "Token generated successfully",authRequest, jwtService.generateToken(authRequest.username()));
        } else {
            throw new UsernameNotFoundException("Invalid username or password");
        }
    }

    @GetMapping("/user/{username}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public UserInfo getUser(@PathVariable String username) {
        return service.getUser(username);
    }

    @GetMapping("/user/all")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public Iterable<UserInfo> getAllUsers() {
        return service.getAllUsers();
    }

    @DeleteMapping("/user/{username}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ApiResponse deleteUser(@PathVariable String username) {
        if (service.deleteUser(username)) {
            return new ApiResponse(true, "User deleted successfully", null);
        } else {
            return new ApiResponse(false, "User not found", null);
        }
    }

    @PutMapping("/user/{username}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ApiResponse updateUser(@PathVariable String username, @RequestBody UserInfo userInfo) {
        if (service.updateUser(username, userInfo)) {
            return new ApiResponse(true, "User updated successfully", null);
        } else {
            return new ApiResponse(false, "User not found", null);
        }
    }

    @GetMapping("/user/{username}/roles")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ApiResponse getUserRoles(@PathVariable String username) {
        UserInfo user = service.getUser(username);
        if (user != null) {
            return new ApiResponse(true, "Roles of user " + username, user.getRoles());
        } else {
            return new ApiResponse(false, "User not found", null);
        }
    }

    @PutMapping("/user/{username}/roles")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ApiResponse updateUserRoles(@PathVariable String username, @RequestBody UserInfo userInfo) {
        if (service.updateUser(username, userInfo)) {
            return new ApiResponse(true, "Roles of user " + username + " updated successfully", null);
        } else {
            return new ApiResponse(false, "User not found", null);
        }
    }

    @GetMapping("/user/{username}/roles/{role}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ApiResponse getUserRole(@PathVariable String username, @PathVariable String role) {
        UserInfo user = service.getUser(username);
        if (user != null) {
            return new ApiResponse(true, "Role of user " + username, user.getRoles());
        } else {
            return new ApiResponse(false, "User not found", null);
        }
    }

}