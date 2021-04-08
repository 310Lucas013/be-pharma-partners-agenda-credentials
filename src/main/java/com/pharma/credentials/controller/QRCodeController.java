package com.pharma.credentials.controller;

import com.google.zxing.WriterException;
import com.pharma.credentials.config.JwtTokenUtil;
import com.pharma.credentials.models.Code;
import com.pharma.credentials.models.JwtResponse;
import com.pharma.credentials.models.UserDto;
import com.pharma.credentials.service.JwtUserDetailsService;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.net.UnknownHostException;
import java.security.Principal;

import static dev.samstevens.totp.util.Utils.getDataUriForImage;

@RestController
@CrossOrigin(origins = "http://localhost:4201")
public class QRCodeController {
    @Autowired
    JwtUserDetailsService userDetailsService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @GetMapping(value = "/barcode")
    public String getbarcode(Principal user) throws WriterException, QrGenerationException {
        SecretGenerator secretGenerator = new DefaultSecretGenerator(64);
        String secret = secretGenerator.generate();

        UserDto userDao = userDetailsService.findUserByUsername(user.getName());
        userDao.setSecret(secret);

        userDetailsService.update(userDao);

        QrData data = new QrData.Builder()
                .label("medicom agenda")
                .secret(secret)
                .issuer("proftaak")
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

        return qrCodeImage;
    }

//    @RequestMapping(value = "/verify", method = RequestMethod.POST)
//    public ResponseEntity<?> verify(@RequestBody Code code, Principal user) throws Exception {
//        System.out.println("verify");
//        UserDto userDto = userDetailsService.findUserByUsername(user.getName());
//        final UserDetails userDetails = userDetailsService.loadUserByUsername(user.getName());
//        if(userDetailsService.findUserByUsername(userDetails.getUsername()) == null)
//            throw new UsernameNotFoundException("Username not found : " + userDetails.getUsername());
//
//        if (userDto == null)
//            throw new UsernameNotFoundException("Username not found : " + user.getName());
//
//        if(userDto.getSecret().isEmpty()){
//            throw new Exception("code not found");
//        }
//
//        TimeProvider timeProvider = new SystemTimeProvider();
//        DefaultCodeGenerator codeGenerator = new DefaultCodeGenerator(HashingAlgorithm.SHA1, 6);
//        CodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);
//
//        if (verifier.isValidCode(userDto.getSecret(), code.getCode())) {
//            userDto.setAuthenticated(true);
//            userDetailsService.update(userDto);
//            final String token = jwtTokenUtil.generateToken(userDetails);
//            return ResponseEntity.ok(new JwtResponse(token));
//        }
//
//        throw new Exception("code not correct");
//    }
}
