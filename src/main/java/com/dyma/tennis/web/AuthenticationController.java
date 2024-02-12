package com.dyma.tennis.web;

import com.dyma.tennis.UserAuthentication;
import com.dyma.tennis.UserCredentials;
import com.dyma.tennis.security.JwtService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "Authentication API")
@RestController
@RequestMapping("/authentication")
public class AuthenticationController {

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationManagerBuilder authenticationManagerBuilder;

    @Operation(summary = "Authenticates user", description = "Authenticates user")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User authentication",
                    content = {@Content(mediaType = "application/json",
                            schema = @Schema(implementation = UserCredentials.class))})

    })
    @PostMapping
    public ResponseEntity<UserAuthentication> authorize(@RequestBody UserCredentials userCredentials) {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                userCredentials.getUsername(),
                userCredentials.getPassword()
        );

        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = jwtService.createToken(authentication);
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setBearerAuth(jwt);
        return new ResponseEntity<UserAuthentication>(new UserAuthentication(authentication.getName(), jwt), httpHeaders, HttpStatus.OK);
    }
}
