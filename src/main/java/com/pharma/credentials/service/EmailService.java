package com.pharma.credentials.service;


import org.springframework.stereotype.Service;

import javax.mail.*;
import javax.mail.internet.*;
import java.util.Properties;

@Service
public class EmailService {
    private static final String username="fhict.supp0rt@gmail.com";
    private static final String password = "FontysSupport404";

    public boolean sendEmail(String emailid, String twoFaCode) throws AddressException, MessagingException {
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");

        Session session = Session.getInstance(props,
                new javax.mail.Authenticator() {
                    protected PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(username, password);
                    }
                });

        MimeMessage message = new MimeMessage(session);
        message.setFrom(new InternetAddress(username));
        message.addRecipient(Message.RecipientType.TO, new InternetAddress(emailid));

        message.setSubject("Two Factor Authentication code from our Service");
        message.setText("Your Two Factor Authentication code is:"+twoFaCode);
        Transport.send(message);
        return true;
    }
}
