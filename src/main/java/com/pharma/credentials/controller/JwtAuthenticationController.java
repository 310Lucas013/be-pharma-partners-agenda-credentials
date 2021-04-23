package com.pharma.credentials.controller;

import com.pharma.credentials.config.JwtTokenUtil;
import com.pharma.credentials.models.*;
import com.pharma.credentials.service.JwtUserDetailsService;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

import static dev.samstevens.totp.util.Utils.getDataUriForImage;

@RestController
@RequestMapping("/credentials")
public class JwtAuthenticationController {
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private JwtUserDetailsService userDetailsService;

    @Value("${qrcode.label}")
    private String qrLabel;

    @Value("${qrcode.issuer}")
    private String qrIssuer;

    @RequestMapping(value = "/authenticate", method = RequestMethod.POST)
    public ResponseEntity<?> createAuthenticationToken(@RequestBody JwtRequest authenticationRequest) throws Exception {
        System.out.println("authenticate");
        authenticate(authenticationRequest.getUsername(), authenticationRequest.getPassword());

        final UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsername());
        if (userDetailsService.findUserByUsername(userDetails.getUsername()) == null)
            throw new UsernameNotFoundException("Username not found : " + userDetails.getUsername());

        final UserDto user = userDetailsService.findUserByUsername(userDetails.getUsername());

        if (!user.isUsing2Fa()) {
            user.setAuthenticated(true);
        } else {
            user.setAuthenticated(false);
        }
        userDetailsService.update(user);

        final String token = jwtTokenUtil.generateToken(userDetails, userDetailsService.findUserIdByName(user.getUsername()).toString());
        return ResponseEntity.ok(new JwtResponse(token));
    }

    @RequestMapping(value = "/register", method = RequestMethod.POST)
    public ResponseEntity<?> saveUser(@RequestBody UserDto user) throws Exception {
        // check if username exist


        user.setAuthenticated(false);

        // generate qr code
        if (user.isUsing2Fa()) {
            SecretGenerator secretGenerator = new DefaultSecretGenerator(64);
            String secret = secretGenerator.generate();
            user.setSecret(secret);

            QrData data = new QrData.Builder()
                    .label(qrLabel)
                    .secret(secret)
                    .issuer(qrIssuer)
                    .algorithm(HashingAlgorithm.SHA1)
                    .digits(6)
                    .period(30)
                    .build();

            QrGenerator generator = new ZxingPngQrGenerator();

            // Generate the QR code image data as a base64 string which
            // can be used in an <img> tag:
            String qrCodeImage = getDataUriForImage(
                    generator.generate(data),
                    generator.getImageMimeType()
            );
            userDetailsService.save(user);

            return ResponseEntity.ok(qrCodeImage);
        }

        return ResponseEntity.ok(userDetailsService.save(user));
    }

    private void authenticate(String username, String password) throws Exception {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (DisabledException e) {
            throw new Exception("USER_DISABLED", e);
        } catch (BadCredentialsException e) {
            throw new Exception("INVALID_CREDENTIALS", e);
        }
    }

    @RequestMapping(value = "/verify", method = RequestMethod.POST)
    public ResponseEntity<?> verify(@RequestBody Code code, Principal user) throws Exception {
        System.out.println("verify");
        UserDto userDto = userDetailsService.findUserByUsername(user.getName());
        final UserDetails userDetails = userDetailsService.loadUserByUsername(user.getName());
        if (userDetailsService.findUserByUsername(userDetails.getUsername()) == null)
            throw new UsernameNotFoundException("Username not found : " + userDetails.getUsername());

        if (userDto == null)
            throw new UsernameNotFoundException("Username not found : " + user.getName());

        if (userDto.getSecret().isEmpty()) {
            throw new Exception("code not found");
        }

        TimeProvider timeProvider = new SystemTimeProvider();
        DefaultCodeGenerator codeGenerator = new DefaultCodeGenerator(HashingAlgorithm.SHA1, 6);
        CodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);

        if (verifier.isValidCode(userDto.getSecret(), code.getCode())) {
            userDto.setAuthenticated(true);
            userDetailsService.update(userDto);
            final String token = jwtTokenUtil.generateToken(userDetails, userDetailsService.findUserIdByName(userDto.getUsername()).toString());
            return ResponseEntity.ok(new JwtResponse(token));
        }

        throw new Exception("code not correct");
    }
}
