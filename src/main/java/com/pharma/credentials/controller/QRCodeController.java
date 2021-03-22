package com.pharma.credentials.controller;

import com.google.zxing.WriterException;
import com.pharma.credentials.config.JwtTokenUtil;
import com.pharma.credentials.models.Code;
import com.pharma.credentials.models.UserDao;
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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.net.UnknownHostException;
import java.security.Principal;

import static dev.samstevens.totp.util.Utils.getDataUriForImage;

@RestController
public class QRCodeController {
    @Autowired
    JwtUserDetailsService userDetailsService;

    @Autowired
    JwtTokenUtil jwtTokenUtil;


    @GetMapping(value = "/barcode")
    public String getbarcode(Principal user) throws WriterException, QrGenerationException {
        SecretGenerator secretGenerator = new DefaultSecretGenerator(64);
        String secret = secretGenerator.generate();

        UserDao userDao = userDetailsService.findUserByUsername(user.getName());
        userDao.setSecret(secret);

        userDetailsService.update(userDao);

        QrData data = new QrData.Builder()
                .label("example@example.com")
                .secret(secret)
                .issuer("Jay")
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

    @RequestMapping(value = "/verify", method = RequestMethod.POST)
    public String verify(@RequestBody Code code, Principal user) throws UnknownHostException {
        UserDao userDao = userDetailsService.findUserByUsername(user.getName());

        TimeProvider timeProvider = new SystemTimeProvider();
        DefaultCodeGenerator codeGenerator = new DefaultCodeGenerator(HashingAlgorithm.SHA1, 6);
        CodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);

        if (verifier.isValidCode(userDao.getSecret(), code.getCode())) {
            userDao.setAuthenticated(true);
            return "CORRECT CODE";
        }

        return "INCORRECT CODE";
    }
}
